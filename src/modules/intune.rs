//! Intune and Defender for Endpoint. Graph is read once per collection up front; the evaluators in
//! `catalog` and `mde` are pure so each rule has a fixture test. Every check goes through `record_one`,
//! so a refused API shows as `Unknown` with the reason instead of vanishing.

mod catalog;
mod mde;

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use super::{record_one, AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use catalog::{AppControlMode, MacroPosture, Outcome, Platform};

const CATEGORY: &str = "Intune";
/// Settings are one call per policy; beyond this many assigned candidates the macro/ASR parse samples.
const POLICY_SETTINGS_LIMIT: usize = 150;

pub struct IntuneModule;

struct IntuneData {
    compliance_classic: Result<Vec<Value>>,
    /// Settings-catalog compliance policies (Linux and newer Windows). Optional: an error is logged, not fatal.
    compliance_catalog: Vec<Value>,
    devices: Result<Vec<Value>>,
    settings: Result<Value>,
    enrollment_configs: Result<Vec<Value>>,
    device_configs: Result<Vec<Value>>,
    config_policies: Result<Vec<Value>>,
    /// `configurationPolicies/{id}/settings` for the assigned endpoint-security and settings-catalog policies.
    policy_settings: HashMap<String, Vec<Value>>,
    approval_policies: Result<Vec<Value>>,
    scope_tags: Result<Vec<Value>>,
    role_assignments: Result<Vec<Value>>,
    wipe_events: Result<Value>,
    /// `None` when the tenant has no Defender for Endpoint plan.
    mde: Option<mde::MdeData>,
}

fn template_family(p: &Value) -> &str {
    p.get("templateReference")
        .and_then(|t| t.get("templateFamily"))
        .and_then(|f| f.as_str())
        .unwrap_or("none")
}

fn is_assigned(v: &Value) -> bool {
    v.get("assignments")
        .and_then(|a| a.as_array())
        .is_some_and(|a| !a.is_empty())
}

fn odata_type(v: &Value) -> &str {
    v.get("@odata.type").and_then(|t| t.as_str()).unwrap_or("")
}

/// Policies whose settings the ASR, macro and App Control checks parse.
fn wants_settings(p: &Value) -> bool {
    if !is_assigned(p) {
        return false;
    }
    let family = template_family(p);
    if family.eq_ignore_ascii_case("endpointSecurityAttackSurfaceReduction")
        || family.eq_ignore_ascii_case("endpointSecurityApplicationControl")
    {
        return true;
    }
    // Plain settings-catalog policies for Windows may carry Office ADMX or ASR settings.
    family.eq_ignore_ascii_case("none")
        && p.get("platforms")
            .and_then(|s| s.as_str())
            .is_some_and(|s| s.to_ascii_lowercase().contains("windows"))
}

async fn collect(graph: &GraphClient, tenant: &TenantInfo) -> IntuneData {
    let (
        compliance_classic,
        compliance_catalog,
        devices,
        settings,
        enrollment_configs,
        device_configs,
        config_policies,
        approval_policies,
        scope_tags,
        role_assignments,
        wipe_events,
    ) = tokio::join!(
        graph.get_all::<Value>(
            "/v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments"
        ),
        graph.get_all::<Value>("/beta/deviceManagement/compliancePolicies?$expand=assignments"),
        graph.get_all::<Value>(
            "/v1.0/deviceManagement/managedDevices?$select=id,operatingSystem,complianceState"
        ),
        graph.get_json("/beta/deviceManagement/settings"),
        graph.get_all::<Value>("/beta/deviceManagement/deviceEnrollmentConfigurations"),
        graph.get_all::<Value>("/beta/deviceManagement/deviceConfigurations?$expand=assignments"),
        graph.get_all::<Value>("/beta/deviceManagement/configurationPolicies?$expand=assignments"),
        graph.get_all::<Value>("/beta/deviceManagement/operationApprovalPolicies"),
        graph.get_all::<Value>("/beta/deviceManagement/roleScopeTags"),
        graph.get_all::<Value>("/beta/deviceManagement/roleAssignments"),
        graph.get_json("/beta/deviceManagement/auditEvents?$top=50&$filter=activityType eq 'Wipe'"),
    );
    let compliance_catalog = compliance_catalog.unwrap_or_else(|e| {
        tracing::warn!("settings-catalog compliance policies unavailable: {e}");
        Vec::new()
    });

    let mut policy_settings = HashMap::new();
    if let Ok(policies) = &config_policies {
        let targets: Vec<&str> = policies
            .iter()
            .filter(|p| wants_settings(p))
            .filter_map(|p| p.get("id").and_then(|i| i.as_str()))
            .take(POLICY_SETTINGS_LIMIT)
            .collect();
        let fetched = futures::future::join_all(targets.iter().map(|id| async move {
            let r = graph
                .get_all::<Value>(&format!(
                    "/beta/deviceManagement/configurationPolicies/{id}/settings"
                ))
                .await;
            (id.to_string(), r)
        }))
        .await;
        for (id, r) in fetched {
            match r {
                Ok(s) => {
                    policy_settings.insert(id, s);
                }
                Err(e) => tracing::warn!("settings for configuration policy {id} unavailable: {e}"),
            }
        }
    }

    let mde = if mde::licensed(tenant) {
        Some(mde::collect(graph).await)
    } else {
        None
    };

    IntuneData {
        compliance_classic,
        compliance_catalog,
        devices,
        settings,
        enrollment_configs,
        device_configs,
        config_policies,
        policy_settings,
        approval_policies,
        scope_tags,
        role_assignments,
        wipe_events,
        mde,
    }
}

fn ok<T>(r: &Result<T>) -> Result<&T> {
    r.as_ref().map_err(|e| anyhow::anyhow!("{e}"))
}

struct Check {
    id: &'static str,
    section: &'static str,
    setting: &'static str,
    description: &'static str,
    expected: &'static str,
    remediation: &'static str,
}

fn emit(findings: &mut Vec<Finding>, registry: &ControlRegistry, c: &Check, outcome: Outcome) {
    let built = outcome.map(|(status, current)| {
        Finding::new(c.id, CATEGORY, c.section, c.setting, c.description)
            .status(status)
            .severity(registry.get_severity(c.id))
            .current_value(current)
            .expected_value(c.expected)
            .remediation(c.remediation)
            .build()
    });
    record_one(findings, built, c.id, CATEGORY, c.section, c.setting);
}

impl IntuneData {
    fn assigned_policies<'a>(&'a self, family: &str) -> Vec<&'a Value> {
        self.config_policies
            .as_ref()
            .map(|ps| {
                ps.iter()
                    .filter(|p| is_assigned(p) && template_family(p).eq_ignore_ascii_case(family))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn settings_of(&self, p: &Value) -> Option<&Vec<Value>> {
        p.get("id")
            .and_then(|i| i.as_str())
            .and_then(|id| self.policy_settings.get(id))
    }

    fn asr(&self) -> Outcome {
        let policies = ok(&self.config_policies)?;
        let asr_policies = self.assigned_policies("endpointSecurityAttackSurfaceReduction");
        let mut rules = std::collections::BTreeMap::new();
        for p in policies.iter().filter(|p| wants_settings(p)) {
            if let Some(s) = self.settings_of(p) {
                for (rule, mode) in catalog::asr_rules(s) {
                    let e = rules.entry(rule).or_insert(mode);
                    if mode > *e {
                        *e = mode;
                    }
                }
            }
        }
        if !asr_policies.is_empty() && asr_policies.iter().all(|p| self.settings_of(p).is_none()) {
            anyhow::bail!(
                "settings of the {} assigned ASR policies could not be read",
                asr_policies.len()
            );
        }
        catalog::asr_001(&rules, asr_policies.len())
    }

    fn macros(&self) -> Outcome {
        let policies = ok(&self.config_policies)?;
        let mut posture = MacroPosture::default();
        for p in policies.iter().filter(|p| wants_settings(p)) {
            if let Some(s) = self.settings_of(p) {
                posture.merge(catalog::macro_settings(s));
            }
        }
        catalog::macro_001(&posture)
    }

    fn app_control(&self) -> Outcome {
        ok(&self.config_policies)?;
        let mut modes: Vec<AppControlMode> = self
            .assigned_policies("endpointSecurityApplicationControl")
            .iter()
            .map(|p| {
                self.settings_of(p)
                    .and_then(|s| catalog::app_control_mode(s))
                    .unwrap_or(AppControlMode::Unknown)
            })
            .collect();
        for c in ok(&self.device_configs)?.iter().filter(|c| is_assigned(c)) {
            let t = odata_type(c);
            if t.ends_with("windows10EndpointProtectionConfiguration") {
                if let Some(m) = catalog::legacy_app_control_mode(c) {
                    modes.push(m);
                }
            }
            if t.ends_with("windows10CustomConfiguration") {
                let applocker = c
                    .get("omaSettings")
                    .and_then(|o| o.as_array())
                    .is_some_and(|o| {
                        o.iter().any(|s| {
                            s.get("omaUri")
                                .and_then(|u| u.as_str())
                                .is_some_and(|u| u.contains("/AppLocker/"))
                        })
                    });
                if applocker {
                    modes.push(AppControlMode::Unknown);
                }
            }
        }
        catalog::wdac_001(&modes)
    }

    fn endpoint_count(&self) -> usize {
        self.devices
            .as_ref()
            .map(|d| {
                catalog::platforms_in_use(d)
                    .into_iter()
                    .filter(|(p, _)| {
                        matches!(p, Platform::Windows | Platform::MacOs | Platform::Linux)
                    })
                    .map(|(_, n)| n)
                    .sum()
            })
            .unwrap_or(0)
    }
}

fn evaluate(d: &IntuneData, tenant: &TenantInfo, registry: &ControlRegistry) -> Vec<Finding> {
    let mut findings = Vec::new();
    let compliance = "Device Compliance";
    let security = "Endpoint Security";
    let admin = "Admin Security";

    let checks: Vec<(Check, Outcome)> = vec![
        (
            Check { id: "INTUNE-COMPLIANCE-001", section: compliance, setting: "Compliance policies per platform", description: "Every platform with enrolled devices has at least one assigned compliance policy", expected: "An assigned compliance policy for each platform in use", remediation: "Create compliance policies per platform (encryption, minimum OS, passcode, Defender risk level) and assign them to all devices under Intune > Devices > Compliance." },
            ok(&d.compliance_classic).and_then(|c| catalog::compliance_001(c, &d.compliance_catalog, ok(&d.devices)?)),
        ),
        (
            Check { id: "INTUNE-COMPLIANCE-002", section: compliance, setting: "Devices with no compliance policy", description: "Devices with no compliance policy assigned are marked not compliant", expected: "secureByDefault: true", remediation: "Under Intune > Devices > Compliance > Compliance settings, set 'Mark devices with no compliance policy assigned as' to Not compliant." },
            ok(&d.settings).and_then(catalog::compliance_002),
        ),
        (
            Check { id: "INTUNE-ENROLL-001", section: "Device Enrollment", setting: "Personal device enrollment", description: "The default platform restrictions block personally owned devices", expected: "Personally owned devices blocked on every allowed platform", remediation: "Under Intune > Devices > Enrollment > Device platform restrictions, edit the default policy and block personally owned devices for each platform." },
            ok(&d.enrollment_configs).and_then(|c| catalog::enroll_001(c)),
        ),
        (
            Check { id: "INTUNE-MULTIAPPROVAL-001", section: admin, setting: "Multi-admin approval", description: "Multi-admin approval policies with an approver group cover device wipe, retire and delete, scripts and apps", expected: "Approval policies for deviceWipe, deviceRetire, deviceDelete (or deviceAction), script and app with approvers", remediation: "Under Intune > Tenant administration > Multi admin approval, create access policies for device actions, scripts and apps with a dedicated approver group." },
            ok(&d.approval_policies).and_then(|p| catalog::multiapproval_001(p)),
        ),
        (
            Check { id: "INTUNE-UPDATE-001", section: "Software Updates", setting: "Windows update rings", description: "Windows quality updates install within a month: deferral of 7 days or less, feature deferral of 30 or less, deadlines set, or Windows Autopatch", expected: "An assigned ring with quality deferral <= 7 days, feature deferral <= 30 days and a quality deadline, or Autopatch", remediation: "Under Intune > Devices > Windows updates, create update rings with short deferrals and deadlines (or enrol in Windows Autopatch) and assign them to all Windows devices." },
            ok(&d.device_configs).and_then(|c| catalog::update_001(c)),
        ),
        (
            Check { id: "INTUNE-ASR-001", section: security, setting: "Attack surface reduction rules", description: "ASR rules for Office child processes, Win32 API from macros, executable email content and LSASS credential theft are in block mode", expected: "Required ASR rules in Block on all Windows devices", remediation: "Under Intune > Endpoint security > Attack surface reduction, set the required rules to Block (audit first, then enforce) and assign to all Windows devices." },
            d.asr(),
        ),
        (
            Check { id: "INTUNE-MACRO-001", section: security, setting: "Office macro settings", description: "Settings-catalog Office policies block macros from the internet and disable VBA macros without notification for Word, Excel and PowerPoint", expected: "Block macros from running in Office files from the Internet: enabled; VBA Macro Notification Settings: disable all without notification", remediation: "Create a settings-catalog policy with the Office ADMX macro settings per app, assign it to all users, and scope an exception group for documented macro needs." },
            d.macros(),
        ),
        (
            Check { id: "INTUNE-WDAC-001", section: security, setting: "App Control for Business", description: "An App Control for Business (or AppLocker) policy is assigned in enforce mode", expected: "At least one assigned application control policy enforcing an allow list", remediation: "Under Intune > Endpoint security > App Control for Business, deploy a policy in audit mode with Intune as a managed installer, review events, then switch to enforce." },
            d.app_control(),
        ),
        (
            Check { id: "INTUNE-ENCRYPTION-001", section: security, setting: "Disk encryption", description: "BitLocker (and FileVault where macOS is managed) policies are assigned", expected: "Disk encryption policy assigned for Windows and macOS", remediation: "Under Intune > Endpoint security > Disk encryption, create BitLocker and FileVault policies and assign them to all devices." },
            ok(&d.config_policies).and_then(|p| catalog::encryption_001(p, ok(&d.device_configs)?, ok(&d.devices)?)),
        ),
        (
            Check { id: "INTUNE-SECURITY-001", section: security, setting: "Security baseline", description: "An antivirus policy or security baseline and an ASR policy are assigned", expected: "Antivirus (or security baseline) and ASR policies assigned", remediation: "Under Intune > Endpoint security, assign the Windows security baseline or an antivirus policy plus an attack surface reduction policy to all Windows devices." },
            ok(&d.config_policies).and_then(|p| catalog::security_001(p)),
        ),
        (
            Check { id: "INTUNE-RBAC-001", section: "RBAC", setting: "Role assignment scope tags", description: "Intune role assignments are limited with custom scope tags", expected: "Every role assignment carries a custom scope tag", remediation: "Under Intune > Tenant administration > Roles, add scope tags to role assignments so delegated admins only see their devices." },
            ok(&d.role_assignments).and_then(|a| catalog::rbac_001(a)),
        ),
    ];
    for (check, outcome) in checks {
        emit(&mut findings, registry, &check, outcome);
    }

    // INTUNE-SCOPETAGS-001: custom scope tags exist (the default tag always does).
    emit(
        &mut findings,
        registry,
        &Check { id: "INTUNE-SCOPETAGS-001", section: "RBAC", setting: "Scope tags", description: "RBAC scope tags are used to segment management", expected: "At least one custom scope tag", remediation: "Under Intune > Tenant administration > Roles > Scope tags, create scope tags for each delegated administration boundary." },
        ok(&d.scope_tags).map(|tags| {
            if tags.len() > 1 {
                (FindingStatus::Pass, format!("{} scope tags (including default)", tags.len()))
            } else {
                (FindingStatus::Warning, "Only the default scope tag".to_string())
            }
        }),
    );

    // INTUNE-WIPAUDIT-001: recent wipe activity as an attack indicator.
    emit(
        &mut findings,
        registry,
        &Check { id: "INTUNE-WIPAUDIT-001", section: "Audit", setting: "Device wipe activity", description: "Recent device wipe operations are reviewed for unauthorised activity", expected: "No unexplained wipe events", remediation: "Review wipe audit events under Intune > Tenant administration > Audit logs and require multi-admin approval for wipes." },
        ok(&d.wipe_events).map(|e| {
            let n = e["value"].as_array().map(|a| a.len()).unwrap_or(0);
            if n == 0 {
                (FindingStatus::Pass, "No recent wipe events".to_string())
            } else {
                (FindingStatus::Warning, format!("{n} recent wipe events to review"))
            }
        }),
    );

    // Inventory (informational).
    let inventory = "Inventory";
    let info = |id: &'static str,
                setting: &'static str,
                description: &'static str,
                r: &Result<Vec<Value>>,
                noun: &str| {
        let c = Check {
            id,
            section: inventory,
            setting,
            description,
            expected: "Informational",
            remediation: "",
        };
        (
            c,
            ok(r).map(|v| (FindingStatus::Info, format!("{} {noun}", v.len()))),
        )
    };
    for (check, outcome) in [
        info(
            "INTUNE-CONFIG-001",
            "Configuration profiles",
            "Device configuration profiles",
            &d.device_configs,
            "configuration profiles",
        ),
        info(
            "INTUNE-SETTINGS-001",
            "Settings catalog policies",
            "Settings catalog and endpoint security policies",
            &d.config_policies,
            "settings catalog policies",
        ),
        info(
            "INTUNE-DEVICES-001",
            "Managed devices",
            "Devices managed by Intune",
            &d.devices,
            "managed devices",
        ),
    ] {
        emit(&mut findings, registry, &check, outcome);
    }

    // Defender for Endpoint.
    let mde_section = "Defender for Endpoint";
    let onboard = Check { id: "MDE-ONBOARD-001", section: mde_section, setting: "Device onboarding", description: "Intune-managed Windows, macOS and Linux devices are onboarded to Defender for Endpoint and reporting", expected: "At least 95% of managed endpoints onboarded and active", remediation: "Onboard devices through Intune > Endpoint security > Endpoint detection and response, and investigate devices that are inactive or not onboarded in the Defender device inventory." };
    let tamper = Check { id: "MDE-TAMPER-001", section: mde_section, setting: "Tamper protection", description: "Tamper protection is enabled on Defender for Endpoint devices", expected: "Tamper protection on for at least 95% of assessed devices", remediation: "Turn on tamper protection tenant-wide under Defender portal > Settings > Endpoints > Advanced features, and enforce it with an Intune antivirus policy." };
    match &d.mde {
        None => {
            let not_licensed = |c: &Check| {
                Finding::new(c.id, CATEGORY, c.section, c.setting, c.description)
                    .status(FindingStatus::NotLicensed)
                    .severity(registry.get_severity(c.id))
                    .current_value(format!(
                        "No Defender for Endpoint plan found (looked for {})",
                        mde::MDE_PLANS.join(", ")
                    ))
                    .expected_value(c.expected)
                    .remediation("License Defender for Endpoint P1/P2 or Defender for Business, then onboard devices.")
                    .build()
            };
            findings.push(not_licensed(&onboard));
            findings.push(not_licensed(&tamper));
        }
        Some(m) => {
            emit(
                &mut findings,
                registry,
                &onboard,
                ok(&m.machines).and_then(|machines| mde::onboard_001(machines, d.endpoint_count())),
            );
            emit(
                &mut findings,
                registry,
                &tamper,
                ok(&m.tamper).and_then(|(c, t)| mde::tamper_001(*c, *t)),
            );
        }
    }
    let _ = tenant;
    findings
}

#[async_trait]
impl AssessmentModule for IntuneModule {
    fn name(&self) -> &str {
        "Intune"
    }

    fn description(&self) -> &str {
        "Assesses Microsoft Intune device management, endpoint security and Defender for Endpoint coverage"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let data = collect(graph, tenant).await;
        let findings = evaluate(&data, tenant, registry);
        let raw_data = serde_json::json!({
            "managedDeviceCount": data.devices.as_ref().map(|d| d.len()).ok(),
            "platformsInUse": data.devices.as_ref().ok().map(|d| {
                catalog::platforms_in_use(d).into_iter().map(|(p, n)| (p.label().to_string(), n)).collect::<HashMap<_, _>>()
            }),
            "configurationPolicyCount": data.config_policies.as_ref().map(|p| p.len()).ok(),
            "policySettingsRead": data.policy_settings.len(),
            "defenderLicensed": data.mde.is_some(),
        });
        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data,
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::engine::LicenseSku;
    use serde_json::json;

    fn tenant(plans: &[&str]) -> TenantInfo {
        TenantInfo {
            tenant_id: "t".into(),
            display_name: "T".into(),
            verified_domains: vec![],
            primary_domain: "contoso.com".into(),
            license_skus: vec![LicenseSku {
                sku_id: "s".into(),
                sku_part_number: "SPE_E5".into(),
                consumed_units: 1,
                prepaid_units: 1,
                service_plans: plans.iter().map(|p| p.to_string()).collect(),
            }],
        }
    }

    fn registry() -> ControlRegistry {
        ControlRegistry::load(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("controls")
                .as_path(),
        )
        .unwrap()
    }

    fn empty_data() -> IntuneData {
        IntuneData {
            compliance_classic: Ok(vec![]),
            compliance_catalog: vec![],
            devices: Ok(vec![json!({"operatingSystem": "Windows"})]),
            settings: Ok(json!({"secureByDefault": true})),
            enrollment_configs: Ok(vec![]),
            device_configs: Ok(vec![]),
            config_policies: Ok(vec![]),
            policy_settings: HashMap::new(),
            approval_policies: Ok(vec![]),
            scope_tags: Ok(vec![json!({"id": "0"})]),
            role_assignments: Ok(vec![]),
            wipe_events: Ok(json!({"value": []})),
            mde: None,
        }
    }

    #[test]
    fn every_check_is_emitted_even_when_apis_fail() {
        let mut d = empty_data();
        d.config_policies = Err(anyhow::anyhow!(
            "Graph API error [Authorization_RequestDenied]: Insufficient privileges"
        ));
        d.devices = Err(anyhow::anyhow!("HTTP 403 for managedDevices"));
        let findings = evaluate(&d, &tenant(&[]), &registry());
        let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();
        for id in [
            "INTUNE-COMPLIANCE-001",
            "INTUNE-COMPLIANCE-002",
            "INTUNE-ENROLL-001",
            "INTUNE-MULTIAPPROVAL-001",
            "INTUNE-UPDATE-001",
            "INTUNE-ASR-001",
            "INTUNE-MACRO-001",
            "INTUNE-WDAC-001",
            "INTUNE-ENCRYPTION-001",
            "INTUNE-SECURITY-001",
            "INTUNE-RBAC-001",
            "INTUNE-SCOPETAGS-001",
            "INTUNE-WIPAUDIT-001",
            "INTUNE-CONFIG-001",
            "INTUNE-SETTINGS-001",
            "INTUNE-DEVICES-001",
            "MDE-ONBOARD-001",
            "MDE-TAMPER-001",
        ] {
            assert!(ids.contains(&id), "missing {id}");
        }
        let asr = findings
            .iter()
            .find(|f| f.check_id == "INTUNE-ASR-001")
            .unwrap();
        assert_eq!(asr.status, FindingStatus::Unknown);
        assert!(
            asr.current_value.contains("Grant the permission"),
            "{}",
            asr.current_value
        );
        assert!(findings
            .iter()
            .all(|f| f.check_id != "MDE-ONBOARD-001" || f.status == FindingStatus::NotLicensed));
        assert!(!findings.iter().any(|f| f.status == FindingStatus::Review));
    }

    #[test]
    fn unlicensed_defender_is_not_licensed_and_licensed_evaluates() {
        assert!(!mde::licensed(&tenant(&["AAD_PREMIUM"])));
        assert!(mde::licensed(&tenant(&["MDE_LITE"])));
        let mut d = empty_data();
        d.mde = Some(mde::MdeData {
            machines: Ok(vec![
                json!({"onboardingStatus": "Onboarded", "healthStatus": "Active"}),
            ]),
            tamper: Ok((1, 1)),
        });
        let findings = evaluate(&d, &tenant(&["WINDEFATP"]), &registry());
        let onboard = findings
            .iter()
            .find(|f| f.check_id == "MDE-ONBOARD-001")
            .unwrap();
        assert_eq!(
            onboard.status,
            FindingStatus::Pass,
            "{}",
            onboard.current_value
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.check_id == "MDE-TAMPER-001")
                .unwrap()
                .status,
            FindingStatus::Pass
        );
    }

    #[test]
    fn asr_reads_settings_of_assigned_policies_only() {
        let mut d = empty_data();
        let rule = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros";
        let setting = |mode: &str| json!([{"settingInstance": {"settingDefinitionId": rule, "choiceSettingValue": {"value": format!("{rule}_{mode}")}}}]);
        d.config_policies = Ok(vec![
            json!({"id": "p1", "templateReference": {"templateFamily": "endpointSecurityAttackSurfaceReduction"}, "assignments": [{"id": "a"}]}),
            json!({"id": "p2", "templateReference": {"templateFamily": "endpointSecurityAttackSurfaceReduction"}, "assignments": []}),
        ]);
        d.policy_settings
            .insert("p1".into(), setting("audit").as_array().unwrap().clone());
        d.policy_settings
            .insert("p2".into(), setting("block").as_array().unwrap().clone());
        let (status, text) = d.asr().unwrap();
        assert_eq!(status, FindingStatus::Warning);
        assert!(text.contains("Win32 API from macros: audit"), "{text}");

        d.policy_settings.clear();
        assert!(d.asr().is_err());
    }
}
