//! Entra ID / identity and access management checks.
//!
//! Tenant data that several checks share (Conditional Access policies, authentication strengths,
//! the authorization policy, Security Defaults, activated directory roles and the privileged member
//! inventory) is fetched once into [`Ctx`]. Each check returns `Result<Finding>`; a failed fetch
//! surfaces as an `Unknown` finding for every check that needs it, never as a missing check.

mod apps;
mod ca;
mod privileged;
mod settings;

use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingBuilder, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use privileged::{Privileged, RoleTiers};

pub struct IdentityModule;

const CATEGORY: &str = "Identity";

/// Static identity of a check: the same text is used for the real finding and for the `Unknown`
/// finding emitted when the check cannot run.
pub(crate) struct Meta {
    pub id: &'static str,
    pub section: &'static str,
    pub setting: &'static str,
    pub description: &'static str,
}

/// A shared fetch result; the error is kept as text so every dependent check can report it.
pub(crate) type Shared<T> = std::result::Result<T, String>;

pub(crate) fn shared<T>(s: &Shared<T>) -> Result<&T> {
    s.as_ref().map_err(|e| anyhow::anyhow!("{e}"))
}

/// An activated directory role with its direct members.
#[derive(Debug, Clone)]
pub(crate) struct DirectoryRole {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub template_id: String,
    pub name: String,
    pub members: Vec<Value>,
}

pub(crate) struct Ctx<'a> {
    pub graph: &'a GraphClient,
    pub tenant: &'a TenantInfo,
    pub registry: &'a ControlRegistry,
    pub tiers: RoleTiers,
    ca_policies: Shared<Vec<Value>>,
    pub strengths: ca::Strengths,
    authorization_policy: Shared<Value>,
    security_defaults_enabled: Shared<bool>,
    directory_roles: Shared<Vec<DirectoryRole>>,
    privileged: Shared<Privileged>,
}

impl<'a> Ctx<'a> {
    async fn load(
        graph: &'a GraphClient,
        tenant: &'a TenantInfo,
        registry: &'a ControlRegistry,
    ) -> Ctx<'a> {
        let tiers = RoleTiers::load();
        let ca_policies = graph
            .get_all::<Value>("/v1.0/identity/conditionalAccess/policies")
            .await
            .map_err(|e| e.to_string());
        let strengths = match graph
            .get_all::<Value>("/v1.0/policies/authenticationStrengthPolicies")
            .await
        {
            Ok(p) => ca::Strengths::from_policies(&p),
            Err(e) => {
                tracing::warn!(
                    "authenticationStrengthPolicies unavailable, using built-in ids only: {e}"
                );
                ca::Strengths::from_policies(&[])
            }
        };
        let authorization_policy = graph
            .get_json("/v1.0/policies/authorizationPolicy")
            .await
            .map(unwrap_single)
            .map_err(|e| e.to_string());
        let security_defaults_enabled = graph
            .get_json("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy")
            .await
            .map(|p| p["isEnabled"].as_bool().unwrap_or(false))
            .map_err(|e| e.to_string());
        let directory_roles = load_directory_roles(graph).await.map_err(|e| e.to_string());
        let privileged = Privileged::load(graph, tenant, &tiers)
            .await
            .map_err(|e| e.to_string());
        Ctx {
            graph,
            tenant,
            registry,
            tiers,
            ca_policies,
            strengths,
            authorization_policy,
            security_defaults_enabled,
            directory_roles,
            privileged,
        }
    }

    pub fn has_p1(&self) -> bool {
        self.tenant.has_service_plan("AAD_PREMIUM") || self.tenant.has_p2()
    }

    pub fn ca(&self) -> Result<&[Value]> {
        shared(&self.ca_policies).map(Vec::as_slice)
    }

    /// Enabled policies only; report-only and disabled policies do not enforce anything.
    pub fn enabled_ca(&self) -> Result<Vec<&Value>> {
        Ok(self.ca()?.iter().filter(|p| ca::is_enabled(p)).collect())
    }

    pub fn authz(&self) -> Result<&Value> {
        shared(&self.authorization_policy)
    }

    pub fn security_defaults(&self) -> Result<bool> {
        shared(&self.security_defaults_enabled).copied()
    }

    pub fn roles(&self) -> Result<&[DirectoryRole]> {
        shared(&self.directory_roles).map(Vec::as_slice)
    }

    pub fn privileged(&self) -> Result<&Privileged> {
        shared(&self.privileged)
    }

    pub fn finding(&self, meta: &Meta) -> FindingBuilder {
        Finding::new(
            meta.id,
            CATEGORY,
            meta.section,
            meta.setting,
            meta.description,
        )
        .severity(self.registry.get_severity(meta.id))
    }

    pub fn not_licensed(&self, f: FindingBuilder, licence: &str) -> Finding {
        f.status(FindingStatus::NotLicensed)
            .current_value(format!("{licence} not licensed"))
            .remediation(format!("Requires {licence}."))
            .build()
    }
}

/// v1.0 returns the authorization policy as a single object; some tenants still wrap it in `value`.
fn unwrap_single(v: Value) -> Value {
    match v["value"].as_array().and_then(|a| a.first()) {
        Some(first) => first.clone(),
        None => v,
    }
}

async fn load_directory_roles(graph: &GraphClient) -> Result<Vec<DirectoryRole>> {
    let roles: Vec<Value> = graph.get_all("/v1.0/directoryRoles").await?;
    let mut out = Vec::with_capacity(roles.len());
    for r in &roles {
        let id = r["id"].as_str().unwrap_or_default().to_string();
        let members = graph
            .get_all::<Value>(&format!("/v1.0/directoryRoles/{id}/members"))
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("members of role {id} unreadable: {e}");
                Vec::new()
            });
        out.push(DirectoryRole {
            id,
            template_id: r["roleTemplateId"].as_str().unwrap_or_default().to_string(),
            name: r["displayName"].as_str().unwrap_or("Unknown").to_string(),
            members,
        });
    }
    Ok(out)
}

fn rec(findings: &mut Vec<Finding>, result: Result<Finding>, meta: &Meta) {
    super::record_one(
        findings,
        result,
        meta.id,
        CATEGORY,
        meta.section,
        meta.setting,
    );
}

/// A group of checks that share one fetch: on error every id gets its own `Unknown` finding.
fn rec_group(findings: &mut Vec<Finding>, result: Result<Vec<Finding>>, metas: &[&Meta]) {
    match result {
        Ok(f) => findings.extend(f),
        Err(e) => {
            for m in metas {
                super::record_one(
                    findings,
                    Err(anyhow::anyhow!("{e}")),
                    m.id,
                    CATEGORY,
                    m.section,
                    m.setting,
                );
            }
        }
    }
}

/// Per-check results that were produced together (one `Result` per id, in `metas` order).
fn rec_each(findings: &mut Vec<Finding>, results: Vec<Result<Finding>>, metas: &[&Meta]) {
    for (result, meta) in results.into_iter().zip(metas) {
        rec(findings, result, meta);
    }
}

#[async_trait]
impl AssessmentModule for IdentityModule {
    fn name(&self) -> &str {
        "Identity"
    }

    fn description(&self) -> &str {
        "Entra ID / identity and access management security assessment"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let ctx = Ctx::load(graph, tenant, registry).await;
        let mut findings: Vec<Finding> = Vec::new();

        // Admin accounts and privileged access
        rec(
            &mut findings,
            privileged::check_global_admin_count(&ctx),
            &privileged::ENTRA_ADMIN_001,
        );
        rec(
            &mut findings,
            privileged::check_privileged_role_inventory(&ctx),
            &privileged::ENTRA_ADMIN_002,
        );
        rec(
            &mut findings,
            privileged::check_dedicated_admin_accounts(&ctx),
            &privileged::ENTRA_ADMIN_003,
        );
        rec(
            &mut findings,
            privileged::check_stale_admins(&ctx),
            &privileged::ENTRA_ADMIN_004,
        );
        rec(
            &mut findings,
            privileged::check_cloud_only_admins(&ctx),
            &privileged::ENTRA_CLOUDADMIN_001,
        );
        rec(
            &mut findings,
            privileged::check_admin_licence_footprint(&ctx),
            &privileged::ENTRA_CLOUDADMIN_002,
        );
        rec(
            &mut findings,
            privileged::check_synced_global_admins(&ctx),
            &privileged::ENTRA_SYNCADMIN_001,
        );
        rec(
            &mut findings,
            privileged::check_break_glass(&ctx).await,
            &privileged::ENTRA_BREAKGLASS_001,
        );
        rec(
            &mut findings,
            privileged::check_dap(&ctx),
            &privileged::ENTRA_DAP_001,
        );

        // PIM
        rec(
            &mut findings,
            privileged::check_pim_usage(&ctx),
            &privileged::ENTRA_PIM_001,
        );
        let role_policies: Shared<privileged::RolePolicies> = if tenant.has_p2() {
            privileged::RolePolicies::load(&ctx)
                .await
                .map_err(|e| e.to_string())
        } else {
            Err("Entra ID P2 not licensed".to_string())
        };
        rec_each(
            &mut findings,
            privileged::check_pim_policies(&ctx, &role_policies),
            &[
                &privileged::ENTRA_PIM_004,
                &privileged::ENTRA_PIM_005,
                &privileged::ENTRA_PIM_006,
                &privileged::ENTRA_PIM_007,
                &privileged::ENTRA_PIM_008,
                &privileged::ENTRA_PIM_009,
            ],
        );
        let reviews: Shared<Vec<Value>> = if tenant.has_p2() {
            graph
                .get_all::<Value>("/v1.0/identityGovernance/accessReviews/definitions")
                .await
                .map_err(|e| e.to_string())
        } else {
            Err("Entra ID P2 not licensed".to_string())
        };
        rec_each(
            &mut findings,
            privileged::check_access_reviews(&ctx, &reviews),
            &[&privileged::ENTRA_PIM_002, &privileged::ENTRA_PIM_003],
        );

        // Conditional Access
        rec_group(
            &mut findings,
            ca::check_conditional_access_overview(&ctx),
            &[&ca::ENTRA_CA_001, &ca::ENTRA_CA_002, &ca::ENTRA_CA_003],
        );
        rec(
            &mut findings,
            ca::check_mfa_all_users(&ctx),
            &ca::CA_MFA_ALL_001,
        );
        rec(
            &mut findings,
            ca::check_legacy_auth(&ctx),
            &ca::CA_LEGACYAUTH_001,
        );
        rec(
            &mut findings,
            ca::check_mfa_admin(&ctx),
            &ca::CA_MFA_ADMIN_001,
        );
        rec(
            &mut findings,
            ca::check_phishres_admin(&ctx),
            &ca::CA_PHISHRES_001,
        );
        rec(
            &mut findings,
            ca::check_phishres_all(&ctx),
            &ca::CA_PHISHRES_002,
        );
        rec(
            &mut findings,
            ca::check_role_coverage(&ctx),
            &ca::CA_ROLECOVERAGE_001,
        );
        rec(
            &mut findings,
            ca::check_sign_in_risk(&ctx),
            &ca::CA_SIGNINRISK_001,
        );
        rec(
            &mut findings,
            ca::check_user_risk(&ctx),
            &ca::CA_USERRISK_001,
        );
        rec(
            &mut findings,
            ca::check_device_code(&ctx).await,
            &ca::CA_DEVICECODE_001,
        );
        rec(
            &mut findings,
            ca::check_managed_device(&ctx),
            &ca::CA_DEVICE_001,
        );
        rec(
            &mut findings,
            ca::check_register_security_info(&ctx),
            &ca::CA_DEVICE_002,
        );
        rec(
            &mut findings,
            ca::check_mobile_app_protection(&ctx),
            &ca::CA_DEVICE_003,
        );
        rec(
            &mut findings,
            ca::check_exclusions(&ctx).await,
            &ca::CA_EXCLUSION_001,
        );
        rec(
            &mut findings,
            ca::check_admin_session(&ctx),
            &ca::CA_SIGNIN_FREQ_001,
        );
        rec(&mut findings, ca::check_paw(&ctx), &ca::CA_PAW_001);

        // Authentication methods, passwords, Security Defaults, MFA
        let auth_methods = graph
            .get_json("/v1.0/policies/authenticationMethodsPolicy")
            .await;
        rec_each(
            &mut findings,
            settings::check_auth_methods(&ctx, &auth_methods),
            &[
                &settings::ENTRA_AUTHMETHOD_001,
                &settings::ENTRA_AUTHMETHOD_002,
                &settings::ENTRA_AUTHMETHOD_003,
                &settings::ENTRA_AUTHMETHOD_004,
                &settings::ENTRA_AUTHMETHOD_005,
            ],
        );
        rec(
            &mut findings,
            settings::check_passwordless_enabled(&ctx, &auth_methods),
            &settings::ENTRA_PASSWORD_001,
        );
        rec(
            &mut findings,
            settings::check_banned_passwords(&ctx).await,
            &settings::ENTRA_PASSWORD_002,
        );
        rec(
            &mut findings,
            settings::check_sspr(&ctx),
            &settings::ENTRA_SSPR_001,
        );
        rec(
            &mut findings,
            settings::check_security_defaults(&ctx),
            &settings::ENTRA_SECDEFAULT_001,
        );
        rec(
            &mut findings,
            settings::check_mfa_registration(&ctx).await,
            &settings::ENTRA_MFA_001,
        );
        rec(
            &mut findings,
            settings::check_per_user_mfa(&ctx).await,
            &settings::ENTRA_PERUSER_001,
        );
        findings.push(settings::check_linkedin(&ctx));

        // Guests, cross-tenant, devices, hybrid
        rec_group(
            &mut findings,
            settings::check_guest_settings(&ctx),
            &[
                &settings::ENTRA_GUEST_001,
                &settings::ENTRA_GUEST_002,
                &settings::ENTRA_GUEST_003,
            ],
        );
        rec(
            &mut findings,
            settings::check_cross_tenant_access(&ctx).await,
            &settings::ENTRA_XTAP_001,
        );
        let device_policy = graph
            .get_json("/v1.0/policies/deviceRegistrationPolicy")
            .await;
        rec_each(
            &mut findings,
            settings::check_device_registration(&ctx, &device_policy),
            &[
                &settings::ENTRA_DEVICE_001,
                &settings::ENTRA_DEVICE_003,
                &settings::ENTRA_DEVICE_004,
                &settings::ENTRA_DEVICE_005,
            ],
        );
        rec(
            &mut findings,
            settings::check_cloud_authentication(&ctx).await,
            &settings::ENTRA_HYBRID_003,
        );

        // Applications and consent
        rec(
            &mut findings,
            apps::check_user_consent(&ctx),
            &apps::ENTRA_CONSENT_001,
        );
        rec(
            &mut findings,
            apps::check_admin_consent_workflow(&ctx).await,
            &apps::ENTRA_CONSENT_002,
        );
        rec(
            &mut findings,
            apps::check_users_can_register_apps(&ctx),
            &apps::ENTRA_APPS_001,
        );
        let app_data = apps::AppData::load(graph).await;
        rec(
            &mut findings,
            apps::check_sp_inventory(&ctx, &app_data),
            &apps::ENTRA_ENTAPP_001,
        );
        rec(
            &mut findings,
            apps::check_disabled_sps(&ctx, &app_data),
            &apps::ENTRA_ENTAPP_002,
        );
        rec(
            &mut findings,
            apps::check_assignment_required(&ctx, &app_data),
            &apps::ENTRA_ENTAPP_003,
        );
        rec(
            &mut findings,
            apps::check_high_impact_grants(&ctx, &app_data),
            &apps::ENTRA_ENTAPP_004,
        );
        rec(
            &mut findings,
            apps::check_sp_credentials(&ctx, &app_data),
            &apps::ENTRA_ENTAPP_005,
        );
        rec(
            &mut findings,
            apps::check_high_impact_hygiene(&ctx, &app_data).await,
            &apps::ENTRA_ENTAPP_022,
        );
        rec(
            &mut findings,
            apps::check_app_inventory(&ctx, &app_data),
            &apps::ENTRA_APPREG_001,
        );
        rec(
            &mut findings,
            apps::check_app_credential_expiry(&ctx, &app_data),
            &apps::ENTRA_APPREG_002,
        );
        rec(
            &mut findings,
            apps::check_app_permission_count(&ctx, &app_data),
            &apps::ENTRA_APPREG_003,
        );
        rec(
            &mut findings,
            apps::check_privileged_apps_with_secrets(&ctx, &app_data),
            &apps::ENTRA_APPREG_005,
        );
        rec(
            &mut findings,
            apps::check_app_management_policy(&ctx).await,
            &apps::ENTRA_APPREG_006,
        );

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: serde_json::json!({}),
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unwrap_single_handles_both_shapes() {
        let wrapped = json!({"value": [{"allowedToUseSSPR": true}]});
        assert_eq!(unwrap_single(wrapped)["allowedToUseSSPR"], json!(true));
        let plain = json!({"allowedToUseSSPR": false});
        assert_eq!(unwrap_single(plain)["allowedToUseSSPR"], json!(false));
    }

    #[test]
    fn group_errors_produce_one_unknown_per_check() {
        let mut findings = Vec::new();
        rec_group(
            &mut findings,
            Err(anyhow::anyhow!("boom")),
            &[&ca::ENTRA_CA_001, &ca::ENTRA_CA_002, &ca::ENTRA_CA_003],
        );
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| f.status == FindingStatus::Unknown));
        assert_eq!(findings[1].check_id, "ENTRA-CA-002");
    }
}
