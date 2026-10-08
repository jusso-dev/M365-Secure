//! Purview information protection, DLP, alert and communication compliance checks.
//!
//! Sensitivity labels come from Microsoft Graph. DLP, alert and communication compliance policies
//! only exist in Security & Compliance PowerShell; the cmdlets are attempted through the Exchange
//! admin REST API and the usual outcome is `Unknown` with an attestation note.

use anyhow::Result;
use serde_json::Value;

use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use crate::modules::exchange::exo::{
    bool_or, finding, list_preview, name_of, need, str_of, strs_of, Exo,
};
use crate::modules::record_one;

const CATEGORY: &str = "Compliance";

// ─── Sensitivity labels (Graph) ─────────────────────────────────────────────

/// Published labels that are active.
pub fn active_label_names(labels: &[Value]) -> Vec<String> {
    labels
        .iter()
        .filter(|l| bool_or(l, "isActive", true))
        .map(|l| str_of(l, "name").unwrap_or("(unnamed)").to_string())
        .collect()
}

/// Published sensitivity labels. Delegated sign-in reads them under `/me`; the tenant-level path is
/// application-only. Older tenants still answer on the beta policy endpoint.
async fn sensitivity_labels(graph: &GraphClient) -> Result<Vec<Value>> {
    let mut errors = Vec::new();
    for path in [
        "/v1.0/me/security/informationProtection/sensitivityLabels",
        "/beta/me/security/informationProtection/sensitivityLabels",
        "/beta/me/informationProtection/policy/labels",
        "/v1.0/security/informationProtection/sensitivityLabels",
    ] {
        match graph.get_all::<Value>(path).await {
            Ok(v) => return Ok(v),
            Err(e) => errors.push(format!("{path}: {e}")),
        }
    }
    anyhow::bail!("{}", errors.join("; "))
}

/// Label policy settings (default label, mandatory labelling, downgrade justification) for the signed-in user.
async fn label_policy_settings(graph: &GraphClient) -> Result<Value> {
    let mut errors = Vec::new();
    for path in [
        "/v1.0/me/security/informationProtection/labelPolicySettings",
        "/beta/me/security/informationProtection/labelPolicySettings",
        "/beta/security/informationProtection/labelPolicySettings",
    ] {
        match graph.get_json(path).await {
            Ok(v) => return Ok(v),
            Err(e) => errors.push(format!("{path}: {e}")),
        }
    }
    anyhow::bail!("{}", errors.join("; "))
}

pub async fn check_labels(
    graph: &GraphClient,
    registry: &ControlRegistry,
    findings: &mut Vec<Finding>,
) {
    let labels = sensitivity_labels(graph).await;
    record_one(
        findings,
        labels.as_ref().map_err(|e| anyhow::anyhow!("{e}")).map(|labels| {
            let active = active_label_names(labels);
            let mut f = finding(
                registry,
                "COMPLIANCE-LABELS-001",
                CATEGORY,
                "Information Protection",
                "Sensitivity Labels Published",
                "At least one sensitivity label is published to users",
            )
            .status(if active.is_empty() { FindingStatus::Fail } else { FindingStatus::Pass })
            .current_value(if active.is_empty() {
                format!("{} label(s) returned, none active/published", labels.len())
            } else {
                format!("{} active published label(s): {}", active.len(), list_preview(&active, 10))
            })
            .expected_value("One or more active labels published through a label policy")
            .remediation(
                "Purview portal > Information protection > Labels: create the taxonomy (for example Public, General, Confidential, \
                 Highly Confidential) and publish it to all users under Label policies.",
            );
            if !active.is_empty() {
                f = f.affected_resources(active);
            }
            f.build()
        }),
        "COMPLIANCE-LABELS-001",
        CATEGORY,
        "Information Protection",
        "Sensitivity Labels Published",
    );

    let settings = label_policy_settings(graph).await;
    record_one(
        findings,
        settings.map(|s| {
            let default_id = str_of(&s, "defaultLabelId").filter(|id| !id.is_empty());
            let default_name = default_id.and_then(|id| {
                labels
                    .as_ref()
                    .ok()
                    .and_then(|ls| ls.iter().find(|l| str_of(l, "id") == Some(id)))
                    .and_then(|l| str_of(l, "name"))
                    .map(String::from)
            });
            let mandatory = bool_or(&s, "isMandatory", false);
            let justify = bool_or(&s, "isDowngradeJustificationRequired", false);
            finding(
                registry,
                "COMPLIANCE-LABELS-002",
                CATEGORY,
                "Information Protection",
                "Default Sensitivity Label",
                "The label policy applies a default sensitivity label to new documents and emails",
            )
            .status(if default_id.is_some() { FindingStatus::Pass } else { FindingStatus::Fail })
            .current_value(match (default_id, default_name) {
                (Some(id), Some(name)) => format!(
                    "Default label '{}' ({}); mandatory labelling = {}, downgrade justification = {}",
                    name, id, mandatory, justify
                ),
                (Some(id), None) => format!(
                    "Default label id {}; mandatory labelling = {}, downgrade justification = {}",
                    id, mandatory, justify
                ),
                _ => format!(
                    "No default label in the effective label policy; mandatory labelling = {}, downgrade justification = {}",
                    mandatory, justify
                ),
            })
            .expected_value("defaultLabelId set in the label policy that applies to all users")
            .remediation(
                "Purview portal > Information protection > Label policies > edit the policy published to all users > \
                 Policy settings: set Apply this label by default to documents and emails, and require justification to remove or lower a label.",
            )
            .build()
        }),
        "COMPLIANCE-LABELS-002",
        CATEGORY,
        "Information Protection",
        "Default Sensitivity Label",
    );
}

// ─── DLP (Security & Compliance PowerShell) ─────────────────────────────────

/// DLP policies that are enabled and enforcing.
pub fn enforcing_policies(policies: &[Value]) -> Vec<&Value> {
    policies
        .iter()
        .filter(|p| bool_or(p, "Enabled", false))
        .filter(|p| str_of(p, "Mode").is_none_or(|m| m.eq_ignore_ascii_case("Enable")))
        .collect()
}

fn covers(p: &Value, key: &str) -> bool {
    !strs_of(p, key).is_empty()
}

pub fn evaluate_dlp(policies: &[Value]) -> [(FindingStatus, String); 3] {
    let enforcing = enforcing_policies(policies);
    let names: Vec<String> = enforcing.iter().map(|p| name_of(p)).collect();
    let any = (
        if enforcing.is_empty() {
            FindingStatus::Fail
        } else {
            FindingStatus::Pass
        },
        if enforcing.is_empty() {
            format!(
                "{} DLP policy(ies), none enabled in Enforce mode",
                policies.len()
            )
        } else {
            format!(
                "{} enforcing DLP policy(ies): {}",
                enforcing.len(),
                list_preview(&names, 10)
            )
        },
    );
    let teams: Vec<String> = enforcing
        .iter()
        .filter(|p| covers(p, "TeamsLocation"))
        .map(|p| name_of(p))
        .collect();
    let teams_eval = (
        if teams.is_empty() {
            FindingStatus::Fail
        } else {
            FindingStatus::Pass
        },
        if teams.is_empty() {
            "No enforcing DLP policy includes the Teams location".to_string()
        } else {
            format!("Teams covered by: {}", list_preview(&teams, 10))
        },
    );
    let exchange = enforcing.iter().any(|p| covers(p, "ExchangeLocation"));
    let spo = enforcing.iter().any(|p| covers(p, "SharePointLocation"));
    let odb = enforcing.iter().any(|p| covers(p, "OneDriveLocation"));
    let coverage = (
        if exchange && spo && odb {
            FindingStatus::Pass
        } else if exchange || spo || odb {
            FindingStatus::Warning
        } else {
            FindingStatus::Fail
        },
        format!(
            "Exchange {}, SharePoint {}, OneDrive {}",
            if exchange { "covered" } else { "not covered" },
            if spo { "covered" } else { "not covered" },
            if odb { "covered" } else { "not covered" }
        ),
    );
    [any, teams_eval, coverage]
}

pub async fn check_dlp(exo: &Exo<'_>, registry: &ControlRegistry, findings: &mut Vec<Finding>) {
    let policies = exo
        .get_sc("Get-DlpCompliancePolicy", None)
        .await
        .map_err(|e| e.to_string());
    let specs = [
        (
            "COMPLIANCE-DLP-001",
            "DLP Policies Enabled",
            "At least one data loss prevention policy is enabled in Enforce mode",
            "One or more DLP policies with Enabled = True and Mode = Enable",
            "Purview portal > Data loss prevention > Policies: create policies from the Australian privacy and financial templates, \
             test in simulation, then switch to Turn it on right away.",
        ),
        (
            "COMPLIANCE-DLP-002",
            "DLP for Microsoft Teams",
            "An enforcing DLP policy covers Teams chat and channel messages",
            "An enforcing DLP policy with TeamsLocation set",
            "Edit the DLP policy and add Teams chat and channel messages as a location (requires E5 or E5 Compliance for Teams DLP).",
        ),
        (
            "COMPLIANCE-DLP-003",
            "DLP Coverage for Exchange, SharePoint and OneDrive",
            "Enforcing DLP policies cover Exchange email, SharePoint sites and OneDrive accounts",
            "ExchangeLocation, SharePointLocation and OneDriveLocation set across enforcing policies",
            "Edit the DLP policies so Exchange email, SharePoint sites and OneDrive accounts are all selected locations.",
        ),
    ];
    let evaluated = policies.as_deref().map(evaluate_dlp);
    for (i, (id, setting, description, expected, remediation)) in specs.iter().enumerate() {
        record_one(
            findings,
            match &evaluated {
                Ok(results) => {
                    let (status, current) = &results[i];
                    Ok(finding(
                        registry,
                        id,
                        CATEGORY,
                        "Data Loss Prevention",
                        setting,
                        description,
                    )
                    .status(*status)
                    .current_value(current.clone())
                    .expected_value(*expected)
                    .remediation(*remediation)
                    .build())
                }
                Err(e) => Err(anyhow::anyhow!("{e}")),
            },
            id,
            CATEGORY,
            "Data Loss Prevention",
            setting,
        );
    }
}

// ─── Alert policies and communication compliance ────────────────────────────

/// Default (system) alert policies that have been disabled.
pub fn disabled_system_alerts(alerts: &[Value]) -> Vec<String> {
    alerts
        .iter()
        .filter(|a| bool_or(a, "IsSystemRule", false) && bool_or(a, "Disabled", false))
        .map(name_of)
        .collect()
}

pub async fn check_alert_policies(
    exo: &Exo<'_>,
    registry: &ControlRegistry,
    findings: &mut Vec<Finding>,
) {
    let alerts = exo
        .get_sc("Get-ProtectionAlert", None)
        .await
        .map_err(|e| e.to_string());
    record_one(
        findings,
        need(&alerts).map(|rows| {
            let disabled = disabled_system_alerts(rows);
            let system = rows.iter().filter(|a| bool_or(a, "IsSystemRule", false)).count();
            let mut f = finding(
                registry,
                "COMPLIANCE-ALERTPOLICY-001",
                CATEGORY,
                "Monitoring & Alerts",
                "Default Alert Policies Enabled",
                "Microsoft's default alert policies (privilege elevation, malware, forwarding, mass deletion) are enabled",
            )
            .status(if disabled.is_empty() { FindingStatus::Pass } else { FindingStatus::Fail })
            .current_value(if disabled.is_empty() {
                format!("{} default alert policy(ies), all enabled", system)
            } else {
                format!(
                    "{} of {} default alert policy(ies) disabled: {}",
                    disabled.len(),
                    system,
                    list_preview(&disabled, 10)
                )
            })
            .expected_value("No system alert policy with Disabled = True")
            .remediation("Defender portal > Policies & rules > Alert policy: turn each listed default policy back on (Set-ProtectionAlert -Identity <name> -Disabled $false).");
            if !disabled.is_empty() {
                f = f.affected_resources(disabled);
            }
            f.build()
        }),
        "COMPLIANCE-ALERTPOLICY-001",
        CATEGORY,
        "Monitoring & Alerts",
        "Default Alert Policies Enabled",
    );
}

pub async fn check_communication_compliance(
    exo: &Exo<'_>,
    registry: &ControlRegistry,
    findings: &mut Vec<Finding>,
) {
    let policies = exo
        .get_sc("Get-SupervisoryReviewPolicyV2", None)
        .await
        .map_err(|e| e.to_string());
    record_one(
        findings,
        need(&policies).map(|rows| {
            let enabled: Vec<String> = rows.iter().filter(|p| bool_or(p, "Enabled", true)).map(name_of).collect();
            finding(
                registry,
                "COMPLIANCE-COMMS-001",
                CATEGORY,
                "Communication Compliance",
                "Communication Compliance Policies",
                "Communication compliance policies monitor regulated or sensitive communications",
            )
            .status(if enabled.is_empty() { FindingStatus::Fail } else { FindingStatus::Pass })
            .current_value(if enabled.is_empty() {
                "No enabled communication compliance policy".to_string()
            } else {
                format!("{} enabled policy(ies): {}", enabled.len(), list_preview(&enabled, 10))
            })
            .expected_value("At least one enabled communication compliance policy")
            .remediation("Purview portal > Communication compliance > Policies: create a policy from the sensitive information or regulatory compliance template.")
            .build()
        }),
        "COMPLIANCE-COMMS-001",
        CATEGORY,
        "Communication Compliance",
        "Communication Compliance Policies",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn active_labels_counted() {
        let labels = vec![
            json!({"name": "Public", "isActive": true}),
            json!({"name": "Retired", "isActive": false}),
            json!({"name": "General"}),
        ];
        assert_eq!(active_label_names(&labels), vec!["Public", "General"]);
    }

    #[test]
    fn dlp_evaluation_uses_locations_of_enforcing_policies() {
        let policies = vec![
            json!({"Name": "PII", "Enabled": true, "Mode": "Enable", "ExchangeLocation": ["All"], "SharePointLocation": ["All"], "OneDriveLocation": ["All"]}),
            json!({"Name": "Teams test", "Enabled": true, "Mode": "TestWithNotifications", "TeamsLocation": ["All"]}),
            json!({"Name": "Off", "Enabled": false, "TeamsLocation": ["All"]}),
        ];
        let [any, teams, coverage] = evaluate_dlp(&policies);
        assert_eq!(any.0, FindingStatus::Pass);
        assert_eq!(teams.0, FindingStatus::Fail);
        assert_eq!(coverage.0, FindingStatus::Pass);

        let partial = vec![
            json!({"Name": "Mail only", "Enabled": true, "Mode": "Enable", "ExchangeLocation": ["All"]}),
        ];
        assert_eq!(evaluate_dlp(&partial)[2].0, FindingStatus::Warning);
        assert_eq!(evaluate_dlp(&[])[0].0, FindingStatus::Fail);
    }

    #[test]
    fn disabled_default_alerts_listed() {
        let alerts = vec![
            json!({"Name": "Elevation of Exchange admin privilege", "IsSystemRule": true, "Disabled": true}),
            json!({"Name": "Custom", "IsSystemRule": false, "Disabled": true}),
            json!({"Name": "Malware campaign", "IsSystemRule": true, "Disabled": false}),
        ];
        assert_eq!(
            disabled_system_alerts(&alerts),
            vec!["Elevation of Exchange admin privilege"]
        );
    }
}
