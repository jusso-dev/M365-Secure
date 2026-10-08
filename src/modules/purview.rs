//! Purview retention policy checks. Retention policies live in Security & Compliance PowerShell
//! (`Get-RetentionCompliancePolicy`); the cmdlet is attempted through the Exchange admin REST API
//! and every check is `Unknown` when it cannot be reached. Retention labels from Graph are
//! recorded as supporting detail only.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};

use super::exchange::exo::{bool_or, finding, list_preview, name_of, str_of, strs_of, Exo};
use super::{record_one, AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

pub struct PurviewModule;

const CATEGORY: &str = "Purview";
const SECTION: &str = "Data Lifecycle";

/// Enabled retention policies.
pub fn enabled_policies(policies: &[Value]) -> Vec<&Value> {
    policies
        .iter()
        .filter(|p| bool_or(p, "Enabled", false))
        .collect()
}

fn covers(policies: &[&Value], keys: &[&str]) -> Vec<String> {
    policies
        .iter()
        .filter(|p| keys.iter().any(|k| !strs_of(p, k).is_empty()))
        .map(|p| name_of(p))
        .collect()
}

/// Statuses for PURVIEW-RETENTION-001..005 from `Get-RetentionCompliancePolicy` rows.
pub fn evaluate_retention(policies: &[Value]) -> [(FindingStatus, String, Vec<String>); 5] {
    let enabled = enabled_policies(policies);
    let names: Vec<String> = enabled.iter().map(|p| name_of(p)).collect();
    let any = (
        if enabled.is_empty() {
            FindingStatus::Fail
        } else {
            FindingStatus::Pass
        },
        if enabled.is_empty() {
            format!("{} retention policy(ies), none enabled", policies.len())
        } else {
            format!(
                "{} enabled retention policy(ies): {}",
                enabled.len(),
                list_preview(&names, 10)
            )
        },
        names.clone(),
    );
    let workload = |label: &str, keys: &[&str]| {
        let covering = covers(&enabled, keys);
        (
            if covering.is_empty() {
                FindingStatus::Fail
            } else {
                FindingStatus::Pass
            },
            if covering.is_empty() {
                format!("No enabled retention policy includes {}", label)
            } else {
                format!("{} covered by: {}", label, list_preview(&covering, 10))
            },
            covering,
        )
    };
    let exchange = workload(
        "Exchange mailboxes",
        &["ExchangeLocation", "PublicFolderLocation"],
    );
    let teams = workload(
        "Teams chats or channel messages",
        &["TeamsChatLocation", "TeamsChannelLocation"],
    );
    let spo = workload(
        "SharePoint or OneDrive",
        &[
            "SharePointLocation",
            "OneDriveLocation",
            "ModernGroupLocation",
        ],
    );
    let not_enforcing: Vec<String> = enabled
        .iter()
        .filter(|p| !str_of(p, "Mode").is_none_or(|m| m.eq_ignore_ascii_case("Enforce")))
        .map(|p| format!("{} ({})", name_of(p), str_of(p, "Mode").unwrap_or("")))
        .collect();
    let enforce = (
        if enabled.is_empty() {
            FindingStatus::Fail
        } else if not_enforcing.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        },
        if enabled.is_empty() {
            "No enabled retention policy".to_string()
        } else if not_enforcing.is_empty() {
            format!(
                "All {} enabled policy(ies) are in Enforce mode",
                enabled.len()
            )
        } else {
            format!("Not enforcing: {}", list_preview(&not_enforcing, 10))
        },
        not_enforcing,
    );
    [any, exchange, teams, spo, enforce]
}

#[async_trait]
impl AssessmentModule for PurviewModule {
    fn name(&self) -> &str {
        "Purview"
    }

    fn description(&self) -> &str {
        "Microsoft Purview retention policy coverage"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();
        let exo = Exo::new(graph, &tenant.tenant_id);

        let policies = exo
            .get_sc("Get-RetentionCompliancePolicy", None)
            .await
            .map_err(|e| e.to_string());
        let label_count = graph
            .get_json("/beta/security/labels/retentionLabels")
            .await
            .ok()
            .and_then(|d| d["value"].as_array().map(|a| a.len()));

        let specs = [
            (
                "PURVIEW-RETENTION-001",
                "Retention Policies",
                "At least one retention policy is enabled",
                "One or more retention policies with Enabled = True",
                "Purview portal > Data lifecycle management > Microsoft 365 > Retention policies: create a policy that retains and then deletes content to your retention schedule.",
            ),
            (
                "PURVIEW-RETENTION-002",
                "Exchange Retention Coverage",
                "An enabled retention policy covers Exchange mailboxes",
                "ExchangeLocation set on an enabled policy",
                "Edit or create a retention policy with Exchange mailboxes selected as a location.",
            ),
            (
                "PURVIEW-RETENTION-003",
                "Teams Retention Coverage",
                "An enabled retention policy covers Teams chats and channel messages",
                "TeamsChatLocation or TeamsChannelLocation set on an enabled policy",
                "Create a Teams-specific retention policy (Teams locations cannot be combined with other workloads).",
            ),
            (
                "PURVIEW-RETENTION-004",
                "SharePoint and OneDrive Retention Coverage",
                "An enabled retention policy covers SharePoint sites and OneDrive accounts",
                "SharePointLocation or OneDriveLocation set on an enabled policy",
                "Edit or create a retention policy with SharePoint sites and OneDrive accounts selected as locations.",
            ),
            (
                "PURVIEW-RETENTION-005",
                "Retention Policies Enforced",
                "Every enabled retention policy runs in Enforce mode rather than simulation",
                "Mode = Enforce on every enabled policy",
                "Switch simulation policies to Enforce once the review is complete (Set-RetentionCompliancePolicy -Identity <name> -Mode Enforce).",
            ),
        ];
        let evaluated = policies.as_deref().map(evaluate_retention);
        for (i, (id, setting, description, expected, remediation)) in specs.iter().enumerate() {
            record_one(
                &mut findings,
                match &evaluated {
                    Ok(results) => {
                        let (status, current, affected) = &results[i];
                        let mut f = finding(registry, id, CATEGORY, SECTION, setting, description)
                            .status(*status)
                            .current_value(current.clone())
                            .expected_value(*expected)
                            .remediation(*remediation);
                        if !affected.is_empty() {
                            f = f.affected_resources(affected.clone());
                        }
                        Ok(f.build())
                    }
                    Err(e) => Err(anyhow::anyhow!("{e}")),
                },
                id,
                CATEGORY,
                SECTION,
                setting,
            );
        }
        if let Some(n) = label_count {
            for f in findings
                .iter_mut()
                .filter(|f| f.check_id == "PURVIEW-RETENTION-001")
            {
                f.details = Some(json!({ "retentionLabelsDefined": n }));
            }
        }

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: json!({ "retention_policies_readable": policies.is_ok(), "retention_labels": label_count }),
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_coverage_per_workload() {
        let policies = vec![
            json!({"Name": "Mail 7y", "Enabled": true, "Mode": "Enforce", "ExchangeLocation": ["All"]}),
            json!({"Name": "Teams 1y", "Enabled": true, "Mode": "TestWithoutNotifications", "TeamsChatLocation": ["All"]}),
            json!({"Name": "Old", "Enabled": false, "SharePointLocation": ["All"]}),
        ];
        let [any, exchange, teams, spo, enforce] = evaluate_retention(&policies);
        assert_eq!(any.0, FindingStatus::Pass);
        assert_eq!(exchange.0, FindingStatus::Pass);
        assert_eq!(teams.0, FindingStatus::Pass);
        assert_eq!(spo.0, FindingStatus::Fail);
        assert_eq!(enforce.0, FindingStatus::Warning);
        assert_eq!(enforce.2, vec!["Teams 1y (TestWithoutNotifications)"]);
        assert!(evaluate_retention(&[])
            .iter()
            .all(|(s, _, _)| *s == FindingStatus::Fail));
    }
}
