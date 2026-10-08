//! LOG-DIAG-001, LOG-RETENTION-001, LOG-SENTINEL-001 and LOG-DETECT-001: Entra log export, workspace
//! retention, Sentinel connectors/rules and the combined count of enabled detections.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde_json::{json, Value};

use super::{check, eq_ci, str_at, summarise, Ctx};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::auth::Resource;
use crate::graph::GraphClient;
use crate::junction::JunctionGateway;

/// Entra log categories the question needs exported.
pub const REQUIRED_ENTRA_LOGS: [&str; 4] = [
    "SignInLogs",
    "NonInteractiveUserSignInLogs",
    "ServicePrincipalSignInLogs",
    "AuditLogs",
];

const MIN_RETENTION_DAYS: i64 = 365;

/// Enabled detections needed for Pass; 1 to this-minus-one is Warning.
const MIN_DETECTIONS: usize = 10;

/// Sentinel connector kinds that bring Microsoft 365, Entra or Defender data in.
const M365_CONNECTOR_KINDS: [&str; 6] = [
    "Office365",
    "AzureActiveDirectory",
    "MicrosoftThreatProtection",
    "MicrosoftDefenderAdvancedThreatProtection",
    "OfficeATP",
    "AzureActiveDirectoryIdentityProtection",
];

/// crownguard MS-LOG-003 scenarios, matched by keyword against rule display names.
const SCENARIOS: &[(&str, &[&str])] = &[
    ("phishing", &["phish"]),
    (
        "password spray",
        &["spray", "brute force", "password guess"],
    ),
    (
        "app consent",
        &["consent", "oauth", "application permission"],
    ),
    (
        "mass download",
        &["mass download", "download", "exfiltration", "exfil"],
    ),
];

const WORKSPACES_KQL: &str = "resources \
| where type =~ 'microsoft.operationalinsights/workspaces' \
| project id, name, retentionInDays = toint(properties.retentionInDays), sku = tostring(properties.sku.name)";

const SENTINEL_SOLUTIONS_KQL: &str = "resources \
| where type =~ 'microsoft.operationsmanagement/solutions' and name startswith 'SecurityInsights(' \
| project workspaceId = tostring(properties.workspaceResourceId)";

const SENTINEL_ARG_KQL: &str = "resources \
| where type =~ 'microsoft.securityinsightsarg/sentinel' \
| project id";

/// Where the Entra diagnostic settings deliver, for the retention check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DiagTargets {
    /// Lower-cased Log Analytics workspace resource ids.
    pub workspaces: Vec<String>,
    /// Any required category is exported anywhere (workspace, storage, event hub or partner).
    pub exporting: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EntraLogCoverage {
    pub enabled: BTreeSet<String>,
    pub targets: DiagTargets,
    pub other_destinations: usize,
}

/// Union of enabled categories across settings that have a destination.
pub(crate) fn entra_log_coverage(settings: &[Value]) -> EntraLogCoverage {
    let mut cov = EntraLogCoverage::default();
    for s in settings {
        let p = &s["properties"];
        let workspace = str_at(p, "workspaceId");
        let other = [
            "storageAccountId",
            "eventHubAuthorizationRuleId",
            "marketplacePartnerId",
        ]
        .iter()
        .any(|k| !str_at(p, k).is_empty());
        if workspace.is_empty() && !other {
            continue;
        }
        let enabled: Vec<&str> = p["logs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|l| l["enabled"].as_bool() == Some(true))
            .map(|l| str_at(l, "category"))
            .filter(|c| REQUIRED_ENTRA_LOGS.iter().any(|r| eq_ci(r, c)))
            .collect();
        if enabled.is_empty() {
            continue;
        }
        cov.targets.exporting = true;
        for c in enabled {
            cov.enabled.insert(
                REQUIRED_ENTRA_LOGS
                    .iter()
                    .find(|r| eq_ci(r, c))
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| c.to_string()),
            );
        }
        if !workspace.is_empty() {
            let w = workspace.to_ascii_lowercase();
            if !cov.targets.workspaces.contains(&w) {
                cov.targets.workspaces.push(w);
            }
        }
        if other {
            cov.other_destinations += 1;
        }
    }
    cov
}

pub(crate) fn coverage_status(cov: &EntraLogCoverage) -> FindingStatus {
    if REQUIRED_ENTRA_LOGS.iter().all(|r| cov.enabled.contains(*r)) {
        FindingStatus::Pass
    } else if cov.enabled.is_empty() {
        FindingStatus::Fail
    } else {
        FindingStatus::Warning
    }
}

pub(crate) async fn entra_diagnostics(ctx: &Ctx<'_>) -> Result<(Finding, DiagTargets)> {
    let settings = ctx
        .arm_get_all(
            "/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview",
        )
        .await?;
    let cov = entra_log_coverage(&settings);
    let status = coverage_status(&cov);
    let missing: Vec<String> = REQUIRED_ENTRA_LOGS
        .iter()
        .filter(|r| !cov.enabled.contains(**r))
        .map(|r| r.to_string())
        .collect();
    let current = if settings.is_empty() {
        "No Entra ID diagnostic settings exist; sign-in and audit logs stay in Entra for 30 days (7 without a premium licence).".to_string()
    } else {
        format!(
            "{} diagnostic setting(s). Exported categories: {}. Missing: {}. Destinations: {} Log Analytics workspace(s), {} storage/event hub/partner.",
            settings.len(),
            if cov.enabled.is_empty() { "none".to_string() } else { cov.enabled.iter().cloned().collect::<Vec<_>>().join(", ") },
            if missing.is_empty() { "none".to_string() } else { missing.join(", ") },
            cov.targets.workspaces.len(),
            cov.other_destinations
        )
    };
    let finding = check(
        ctx.registry,
        "LOG-DIAG-001",
        "LOGGING",
        "Entra ID diagnostic settings",
        "Sign-in and audit log export",
        "Entra ID diagnostic settings should stream interactive, non-interactive and service principal sign-in logs and audit logs \
to a Log Analytics workspace, Sentinel or a SIEM via Event Hubs, so investigations reach back further than Entra's own retention \
and an attacker with admin rights cannot erase the trail.",
    )
    .status(status)
    .current_value(current)
    .expected_value("SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs and AuditLogs enabled to a destination")
    .remediation(
        "In Entra ID > Diagnostic settings add a setting that sends the four log categories (plus ManagedIdentitySignInLogs and \
RiskyUsers where licensed) to the central Log Analytics workspace or an Event Hub feeding the SIEM.",
    )
    .details(json!({
        "settings": settings.len(),
        "enabledCategories": cov.enabled,
        "missingCategories": missing,
        "workspaces": cov.targets.workspaces,
        "otherDestinations": cov.other_destinations,
    }))
    .build();
    Ok((finding, cov.targets))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RetentionReport {
    pub evaluated: Vec<(String, i64)>,
    pub short: Vec<(String, i64)>,
    pub unmatched_targets: usize,
}

/// Retention of the workspaces the Entra settings target (all workspaces when `targets` is empty).
pub(crate) fn evaluate_retention(workspaces: &[Value], targets: &[String]) -> RetentionReport {
    let by_id: BTreeMap<String, &Value> = workspaces
        .iter()
        .map(|w| (str_at(w, "id").to_ascii_lowercase(), w))
        .collect();
    let selected: Vec<&Value> = if targets.is_empty() {
        workspaces.iter().collect()
    } else {
        targets
            .iter()
            .filter_map(|t| by_id.get(t).copied())
            .collect()
    };
    let evaluated: Vec<(String, i64)> = selected
        .iter()
        .map(|w| {
            (
                str_at(w, "name").to_string(),
                w["retentionInDays"].as_i64().unwrap_or(0),
            )
        })
        .collect();
    RetentionReport {
        short: evaluated
            .iter()
            .filter(|(_, d)| *d < MIN_RETENTION_DAYS)
            .cloned()
            .collect(),
        unmatched_targets: targets.len().saturating_sub(selected.len()),
        evaluated,
    }
}

pub(crate) async fn workspace_retention(
    ctx: &Ctx<'_>,
    targets: Option<&DiagTargets>,
) -> Result<Finding> {
    let Some(targets) = targets else {
        anyhow::bail!("LOG-DIAG-001 did not complete, so the target workspaces are unknown");
    };
    let builder = check(
        ctx.registry,
        "LOG-RETENTION-001",
        "LOGGING",
        "Log Analytics retention",
        "Workspace retention for Entra log targets",
        "The Log Analytics workspaces receiving Entra sign-in and audit logs should keep them for at least 12 months. Intrusions \
are often found months later; Entra's own retention is 30 days.",
    )
    .expected_value(format!(
        "retentionInDays >= {MIN_RETENTION_DAYS} on each target workspace (or table-level total retention covering 12 months)"
    ))
    .remediation(
        "Set the workspace retention to 365 days or more (Log Analytics workspace > Usage and estimated costs > Data retention), \
or configure table-level total retention of at least 12 months for SigninLogs, AADNonInteractiveUserSignInLogs, \
AADServicePrincipalSignInLogs and AuditLogs.",
    );
    if !targets.exporting {
        return Ok(builder
            .status(FindingStatus::Fail)
            .current_value("Entra logs are not exported anywhere, so nothing is retained beyond Entra's 30-day window.")
            .build());
    }
    if targets.workspaces.is_empty() {
        return Ok(builder
            .status(FindingStatus::Info)
            .current_value(
                "Entra logs go to storage, Event Hubs or a partner SIEM rather than a Log Analytics workspace; retention there is \
not visible from Azure. Confirm 12-month retention in the SIEM as attestation.",
            )
            .build());
    }
    let workspaces = ctx.resource_graph(WORKSPACES_KQL).await?;
    let report = evaluate_retention(&workspaces, &targets.workspaces);
    if report.evaluated.is_empty() {
        anyhow::bail!(
            "none of the {} target workspace(s) are readable through Resource Graph; the workspace may be in a subscription the identity cannot see",
            targets.workspaces.len()
        );
    }
    let short: Vec<String> = report
        .short
        .iter()
        .map(|(n, d)| format!("{n} ({d} days)"))
        .collect();
    let all: Vec<String> = report
        .evaluated
        .iter()
        .map(|(n, d)| format!("{n} ({d} days)"))
        .collect();
    let status = if short.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };
    let mut current = if short.is_empty() {
        format!(
            "All {} target workspace(s) retain for at least {MIN_RETENTION_DAYS} days: {}.",
            all.len(),
            summarise(&all, 5)
        )
    } else {
        format!(
            "{} of {} target workspace(s) retain for less than {MIN_RETENTION_DAYS} days: {}. Table-level total retention \
(archive) is not evaluated and may still meet 12 months.",
            short.len(),
            all.len(),
            summarise(&short, 5)
        )
    };
    if report.unmatched_targets > 0 {
        current.push_str(&format!(
            " {} target workspace(s) were not readable.",
            report.unmatched_targets
        ));
    }
    Ok(builder
        .status(status)
        .current_value(current)
        .affected_resources(report.short.iter().map(|(n, _)| n.clone()).collect())
        .details(json!({
            "workspaces": report.evaluated.iter().map(|(n, d)| json!({"name": n, "retentionInDays": d})).collect::<Vec<_>>(),
            "unreadableTargets": report.unmatched_targets,
        }))
        .build())
}

/// Lower-cased workspace resource ids with Sentinel enabled, from either discovery shape.
pub(crate) fn sentinel_workspace_ids(solutions: &[Value], sentinels: &[Value]) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = solutions
        .iter()
        .map(|s| str_at(s, "workspaceId").to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    for s in sentinels {
        let id = str_at(s, "id").to_ascii_lowercase();
        if let Some(pos) = id.find("/providers/microsoft.securityinsightsarg") {
            ids.insert(id[..pos].to_string());
        }
    }
    ids
}

/// `(subscriptionId, resourceGroupName, workspaceName)` from a workspace resource id.
pub(crate) fn parse_workspace_id(id: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = id.split('/').filter(|p| !p.is_empty()).collect();
    let after = |key: &str| {
        parts
            .iter()
            .position(|p| p.eq_ignore_ascii_case(key))
            .and_then(|i| parts.get(i + 1))
            .map(|s| s.to_string())
    };
    Some((
        after("subscriptions")?,
        after("resourceGroups")?,
        after("workspaces")?,
    ))
}

pub(crate) fn enabled_rules(rules: &[Value]) -> Vec<Value> {
    rules
        .iter()
        .filter(|r| r["properties"]["enabled"].as_bool() == Some(true))
        .cloned()
        .collect()
}

pub(crate) fn connector_kinds(connectors: &[Value]) -> BTreeSet<String> {
    connectors
        .iter()
        .map(|c| str_at(c, "kind").to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

pub(crate) fn has_m365_connector(kinds: &BTreeSet<String>) -> bool {
    kinds
        .iter()
        .any(|k| M365_CONNECTOR_KINDS.iter().any(|m| eq_ci(m, k)))
}

/// Scenario -> number of rule names mentioning it.
pub(crate) fn scenario_coverage<'a>(
    names: impl Iterator<Item = &'a str>,
) -> BTreeMap<&'static str, usize> {
    let mut out: BTreeMap<&'static str, usize> = SCENARIOS.iter().map(|(s, _)| (*s, 0)).collect();
    for name in names {
        let lower = name.to_ascii_lowercase();
        for (scenario, keywords) in SCENARIOS {
            if keywords.iter().any(|k| lower.contains(k)) {
                *out.get_mut(scenario).unwrap() += 1;
            }
        }
    }
    out
}

pub(crate) fn detection_status(enabled: usize) -> FindingStatus {
    if enabled >= MIN_DETECTIONS {
        FindingStatus::Pass
    } else if enabled > 0 {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    }
}

fn scenario_text(cov: &BTreeMap<&'static str, usize>) -> String {
    let covered: Vec<String> = cov
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(s, n)| format!("{s} ({n})"))
        .collect();
    let missing: Vec<&str> = cov
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(s, _)| *s)
        .collect();
    format!(
        "Scenario keywords matched: {}; unmatched: {}.",
        if covered.is_empty() {
            "none".to_string()
        } else {
            covered.join(", ")
        },
        if missing.is_empty() {
            "none".to_string()
        } else {
            missing.join(", ")
        }
    )
}

/// LOG-SENTINEL-001 plus the enabled rules, for LOG-DETECT-001.
pub(crate) async fn sentinel(ctx: &Ctx<'_>) -> Result<(Finding, Vec<Value>)> {
    let solutions = ctx.resource_graph(SENTINEL_SOLUTIONS_KQL).await?;
    let sentinels = ctx
        .resource_graph(SENTINEL_ARG_KQL)
        .await
        .unwrap_or_default();
    let workspace_ids = sentinel_workspace_ids(&solutions, &sentinels);
    let builder = check(
        ctx.registry,
        "LOG-SENTINEL-001",
        "LOGGING",
        "Microsoft Sentinel",
        "Data connectors and enabled analytics rules",
        "Microsoft Sentinel workspaces should ingest Microsoft 365, Entra and Defender data through data connectors and run \
enabled analytics rules covering phishing, password spray, app consent grants and mass download.",
    )
    .expected_value(format!(
        "An M365/Entra/Defender data connector and at least {MIN_DETECTIONS} enabled analytics rules"
    ))
    .remediation(
        "Connect the Microsoft Defender XDR (or Office 365 and Entra ID) data connectors, then enable analytics rules from the \
Microsoft content hub solutions for Entra ID, Office 365 and Defender, covering the Entra security operations guide scenarios.",
    );
    if workspace_ids.is_empty() {
        return Ok((
            builder
                .status(FindingStatus::Info)
                .current_value(
                    "No Microsoft Sentinel workspace found in the readable subscriptions; detection may live in Defender XDR \
(see LOG-DETECT-001) or a third-party SIEM.",
                )
                .build(),
            Vec::new(),
        ));
    }
    let mut rules: Vec<Value> = Vec::new();
    let mut kinds: BTreeSet<String> = BTreeSet::new();
    let mut read = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for id in &workspace_ids {
        let Some((sub, rg, name)) = parse_workspace_id(id) else {
            errors.push(format!("{id}: not a workspace id"));
            continue;
        };
        let params = JunctionGateway::params(&[
            ("subscriptionId", &sub),
            ("resourceGroupName", &rg),
            ("workspaceName", &name),
        ]);
        let connectors = ctx
            .jx
            .list(
                Resource::AzureResourceManager,
                "sentinel.securityinsights.data_connectors.list",
                params.clone(),
            )
            .await;
        let alert_rules = ctx
            .jx
            .list(
                Resource::AzureResourceManager,
                "sentinel.securityinsights.alert_rules.list",
                params,
            )
            .await;
        match (connectors, alert_rules) {
            (Ok(c), Ok(r)) => {
                read += 1;
                kinds.extend(connector_kinds(&c));
                rules.extend(enabled_rules(&r));
            }
            (Err(e), _) | (_, Err(e)) => errors.push(format!("{name}: {e}")),
        }
    }
    if read == 0 {
        anyhow::bail!(
            "Sentinel content could not be read for any of {} workspace(s): {}",
            workspace_ids.len(),
            summarise(&errors, 3)
        );
    }
    let rule_names: Vec<String> = rules
        .iter()
        .map(|r| str_at(&r["properties"], "displayName").to_string())
        .collect();
    let scenarios = scenario_coverage(rule_names.iter().map(String::as_str));
    let mut status = detection_status(rules.len());
    let connected = has_m365_connector(&kinds);
    if status == FindingStatus::Pass && !connected {
        status = FindingStatus::Warning;
    }
    let kinds_text: Vec<String> = kinds.iter().cloned().collect();
    let mut current = format!(
        "{} Sentinel workspace(s); {} enabled analytics rule(s). Connectors: {}. {}",
        read,
        rules.len(),
        if kinds_text.is_empty() {
            "none".to_string()
        } else {
            summarise(&kinds_text, 10)
        },
        scenario_text(&scenarios)
    );
    if !connected {
        current.push_str(" No Microsoft 365 / Entra / Defender data connector is present.");
    }
    if !errors.is_empty() {
        current.push_str(&format!(" {} workspace(s) unreadable.", errors.len()));
    }
    let finding = builder
        .status(status)
        .current_value(current)
        .details(json!({
            "workspaces": workspace_ids,
            "connectorKinds": kinds,
            "enabledRules": rules.len(),
            "ruleNames": rule_names,
            "scenarios": scenarios,
            "errors": errors,
        }))
        .build();
    Ok((finding, rules))
}

pub(crate) fn enabled_xdr_rules(rules: &[Value]) -> Vec<Value> {
    rules
        .iter()
        .filter(|r| r["isEnabled"].as_bool() == Some(true))
        .cloned()
        .collect()
}

/// LOG-DETECT-001: Defender XDR custom detections plus Sentinel analytics rules (when available).
pub(crate) async fn detections(
    graph: &GraphClient,
    registry: &ControlRegistry,
    sentinel_rules: Option<&[Value]>,
) -> Result<Finding> {
    let xdr = graph
        .get_all::<Value>("/beta/security/rules/detectionRules")
        .await;
    let (xdr_enabled, xdr_error) = match xdr {
        Ok(rules) => (Some(enabled_xdr_rules(&rules)), None),
        Err(e) => (None, Some(e.to_string())),
    };
    if xdr_enabled.is_none() && sentinel_rules.is_none() {
        anyhow::bail!(
            "neither Defender XDR custom detections nor Sentinel rules were readable: {}. Custom detections need the \
CustomDetection.Read.All Graph permission.",
            xdr_error.unwrap_or_default()
        );
    }
    let sentinel_count = sentinel_rules.map(<[Value]>::len).unwrap_or(0);
    let xdr_count = xdr_enabled.as_ref().map(Vec::len).unwrap_or(0);
    let total = sentinel_count + xdr_count;
    let names: Vec<String> = sentinel_rules
        .into_iter()
        .flatten()
        .map(|r| str_at(&r["properties"], "displayName").to_string())
        .chain(
            xdr_enabled
                .iter()
                .flatten()
                .map(|r| str_at(r, "displayName").to_string()),
        )
        .collect();
    let scenarios = scenario_coverage(names.iter().map(String::as_str));
    let mut current = format!(
        "{total} enabled detection(s): {sentinel_count} Sentinel analytics rule(s), {} Defender XDR custom detection(s). {}",
        xdr_enabled
            .as_ref()
            .map(|v| v.len().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        scenario_text(&scenarios)
    );
    if let Some(e) = &xdr_error {
        current.push_str(&format!(
            " Defender XDR custom detections not readable: {e}"
        ));
    }
    if sentinel_rules.is_none() {
        current.push_str(
            " Sentinel rules not included (Azure not readable or no Sentinel workspace).",
        );
    }
    current.push_str(
        " Built-in Defender XDR alerts and Entra ID Protection detections are not counted; routing to on-call is attestation.",
    );
    Ok(check(
        registry,
        "LOG-DETECT-001",
        "LOGGING",
        "Detection rules",
        "Enabled analytics and custom detection rules",
        "Detection rules in Sentinel or Defender XDR should fire on privileged role assignments outside PIM, Conditional Access \
changes, emergency account sign-ins and new credentials on applications, and route to someone on call.",
    )
    .status(detection_status(total))
    .current_value(current)
    .expected_value(format!(
        "At least {MIN_DETECTIONS} enabled detection rules across Sentinel and Defender XDR, covering the Entra security operations scenarios"
    ))
    .remediation(
        "Build detections from the Microsoft Entra security operations guides (privileged accounts, applications) as Sentinel \
analytics rules or Defender XDR custom detections, starting with emergency account sign-in and role assignment changes, and \
test each alert end to end.",
    )
    .details(json!({
        "sentinelEnabledRules": sentinel_count,
        "xdrEnabledRules": xdr_enabled.as_ref().map(Vec::len),
        "xdrError": xdr_error,
        "scenarios": scenarios,
        "ruleNames": names,
    }))
    .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setting(workspace: &str, categories: &[(&str, bool)]) -> Value {
        json!({"properties": {
            "workspaceId": workspace,
            "logs": categories.iter().map(|(c, e)| json!({"category": c, "enabled": e})).collect::<Vec<_>>(),
        }})
    }

    #[test]
    fn entra_coverage_unions_settings_with_destinations() {
        let settings = vec![
            setting("/subscriptions/S/resourceGroups/RG/providers/Microsoft.OperationalInsights/workspaces/WS",
                &[("SignInLogs", true), ("AuditLogs", true), ("NonInteractiveUserSignInLogs", false)]),
            setting("", &[("ServicePrincipalSignInLogs", true)]), // no destination: ignored
            json!({"properties": {"eventHubAuthorizationRuleId": "/eh", "logs": [{"category": "NonInteractiveUserSignInLogs", "enabled": true}]}}),
        ];
        let cov = entra_log_coverage(&settings);
        assert_eq!(cov.enabled.len(), 3);
        assert!(!cov.enabled.contains("ServicePrincipalSignInLogs"));
        assert_eq!(cov.targets.workspaces, vec![
            "/subscriptions/s/resourcegroups/rg/providers/microsoft.operationalinsights/workspaces/ws".to_string()
        ]);
        assert_eq!(cov.other_destinations, 1);
        assert!(cov.targets.exporting);
        assert_eq!(coverage_status(&cov), FindingStatus::Warning);
        assert_eq!(
            coverage_status(&entra_log_coverage(&[])),
            FindingStatus::Fail
        );
        let full = vec![setting("/w", &REQUIRED_ENTRA_LOGS.map(|c| (c, true)))];
        assert_eq!(
            coverage_status(&entra_log_coverage(&full)),
            FindingStatus::Pass
        );
    }

    #[test]
    fn retention_filters_to_targets() {
        let workspaces = vec![
            json!({"id": "/W1", "name": "w1", "retentionInDays": 730}),
            json!({"id": "/W2", "name": "w2", "retentionInDays": 90}),
            json!({"id": "/W3", "name": "w3", "retentionInDays": 30}),
        ];
        let report = evaluate_retention(
            &workspaces,
            &["/w1".into(), "/w2".into(), "/missing".into()],
        );
        assert_eq!(report.evaluated.len(), 2);
        assert_eq!(report.short, vec![("w2".to_string(), 90)]);
        assert_eq!(report.unmatched_targets, 1);
        assert_eq!(evaluate_retention(&workspaces, &[]).evaluated.len(), 3);
    }

    #[test]
    fn sentinel_workspaces_from_both_shapes() {
        let solutions = vec![
            json!({"workspaceId": "/subscriptions/S/resourceGroups/RG/providers/Microsoft.OperationalInsights/workspaces/A"}),
        ];
        let sentinels = vec![
            json!({"id": "/subscriptions/s/resourcegroups/rg/providers/microsoft.operationalinsights/workspaces/b/providers/microsoft.securityinsightsarg/sentinel/b"}),
        ];
        let ids = sentinel_workspace_ids(&solutions, &sentinels);
        assert_eq!(ids.len(), 2);
        let (sub, rg, name) = parse_workspace_id(ids.iter().next().unwrap()).unwrap();
        assert_eq!((sub.as_str(), rg.as_str(), name.as_str()), ("s", "rg", "a"));
        assert!(parse_workspace_id("/subscriptions/s").is_none());
    }

    #[test]
    fn rules_connectors_and_scenarios() {
        let rules = vec![
            json!({"kind": "Scheduled", "properties": {"enabled": true, "displayName": "Possible password spray"}}),
            json!({"kind": "Scheduled", "properties": {"enabled": false, "displayName": "Phishing link clicked"}}),
            json!({"kind": "Fusion", "properties": {"enabled": true, "displayName": "Suspicious OAuth consent grant"}}),
        ];
        let enabled = enabled_rules(&rules);
        assert_eq!(enabled.len(), 2);
        let cov = scenario_coverage(
            enabled
                .iter()
                .map(|r| str_at(&r["properties"], "displayName")),
        );
        assert_eq!(cov["password spray"], 1);
        assert_eq!(cov["app consent"], 1);
        assert_eq!(cov["phishing"], 0);
        let kinds = connector_kinds(&[
            json!({"kind": "MicrosoftThreatProtection"}),
            json!({"kind": "ThreatIntelligence"}),
        ]);
        assert!(has_m365_connector(&kinds));
        assert!(!has_m365_connector(&connector_kinds(&[
            json!({"kind": "ThreatIntelligence"})
        ])));
        assert_eq!(detection_status(0), FindingStatus::Fail);
        assert_eq!(detection_status(3), FindingStatus::Warning);
        assert_eq!(detection_status(10), FindingStatus::Pass);
        assert_eq!(
            enabled_xdr_rules(&[json!({"isEnabled": true}), json!({"isEnabled": false})]).len(),
            1
        );
    }
}
