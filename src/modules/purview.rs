use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct PurviewModule;

#[async_trait]
impl AssessmentModule for PurviewModule {
    fn name(&self) -> &str {
        "Purview"
    }

    fn description(&self) -> &str {
        "Assesses Microsoft Purview data governance, retention policies, and labels"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        _tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        // PURVIEW-RETENTION-001: Retention labels exist
        match graph
            .get_json("/beta/security/labels/retentionLabels")
            .await
        {
            Ok(data) => {
                let labels = data["value"].as_array();
                let label_count = labels.map(|a| a.len()).unwrap_or(0);

                let status = if label_count > 0 {
                    FindingStatus::Pass
                } else {
                    FindingStatus::Fail
                };

                findings.push(
                    Finding::new(
                        "PURVIEW-RETENTION-001",
                        "Purview",
                        "Data Lifecycle",
                        "Retention Labels",
                        "Check that retention labels are defined for data governance",
                    )
                    .status(status)
                    .severity(registry.get_severity("PURVIEW-RETENTION-001"))
                    .current_value(format!("{} retention labels configured", label_count))
                    .expected_value("At least 1 retention label should be configured")
                    .remediation(
                        "Create retention labels in Microsoft Purview compliance portal > Data lifecycle management > Retention labels.",
                    )
                    .build(),
                );

                // PURVIEW-RETENTION-002: Check label details
                if let Some(label_arr) = labels {
                    let labels_with_retention: Vec<&serde_json::Value> = label_arr
                        .iter()
                        .filter(|l| {
                            l["retentionDuration"].as_object().is_some()
                                || l["retentionTrigger"].as_str().is_some()
                        })
                        .collect();

                    let status = if !labels_with_retention.is_empty() {
                        FindingStatus::Pass
                    } else if label_count > 0 {
                        FindingStatus::Warning
                    } else {
                        FindingStatus::Fail
                    };

                    findings.push(
                        Finding::new(
                            "PURVIEW-RETENTION-002",
                            "Purview",
                            "Data Lifecycle",
                            "Retention Duration Configuration",
                            "Check that retention labels have retention durations configured",
                        )
                        .status(status)
                        .severity(registry.get_severity("PURVIEW-RETENTION-002"))
                        .current_value(format!(
                            "{} of {} labels have retention durations configured",
                            labels_with_retention.len(),
                            label_count
                        ))
                        .expected_value("Retention labels should have durations configured")
                        .remediation(
                            "Edit retention labels to specify retention duration and action (retain, delete, or both). Navigate to Purview > Data lifecycle management.",
                        )
                        .build(),
                    );

                    // PURVIEW-RETENTION-003: Check for auto-apply labels
                    let auto_apply_labels: Vec<&serde_json::Value> = label_arr
                        .iter()
                        .filter(|l| l["isInUse"].as_bool().unwrap_or(false))
                        .collect();

                    findings.push(
                        Finding::new(
                            "PURVIEW-RETENTION-003",
                            "Purview",
                            "Data Lifecycle",
                            "Retention Label Deployment",
                            "Check that retention labels are actively published or auto-applied",
                        )
                        .status(if !auto_apply_labels.is_empty() {
                            FindingStatus::Pass
                        } else {
                            FindingStatus::Warning
                        })
                        .severity(registry.get_severity("PURVIEW-RETENTION-003"))
                        .current_value(format!("{} of {} labels are in use", auto_apply_labels.len(), label_count))
                        .expected_value("Retention labels should be published and actively applied")
                        .remediation(
                            "Publish retention labels via label policies or configure auto-apply rules. Navigate to Purview > Data lifecycle management > Label policies.",
                        )
                        .build(),
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Failed to check retention labels: {}", e);
                findings.push(
                    Finding::new(
                        "PURVIEW-RETENTION-001",
                        "Purview",
                        "Data Lifecycle",
                        "Retention Labels",
                        "Failed to check retention labels",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("PURVIEW-RETENTION-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Retention labels should be accessible")
                    .build(),
                );
            }
        }

        // PURVIEW-RETENTION-004: Retention event types
        match graph
            .get_json("/beta/security/triggerTypes/retentionEventTypes")
            .await
        {
            Ok(data) => {
                let event_types = data["value"].as_array().map(|a| a.len()).unwrap_or(0);

                findings.push(
                    Finding::new(
                        "PURVIEW-RETENTION-004",
                        "Purview",
                        "Data Lifecycle",
                        "Retention Event Types",
                        "Check that event-based retention triggers are configured for compliance scenarios",
                    )
                    .status(if event_types > 0 {
                        FindingStatus::Pass
                    } else {
                        FindingStatus::Info
                    })
                    .severity(registry.get_severity("PURVIEW-RETENTION-004"))
                    .current_value(format!("{} retention event types configured", event_types))
                    .expected_value("Event-based retention types for regulatory compliance scenarios")
                    .remediation(
                        "Configure event-based retention for scenarios like employee departure or contract expiration. Navigate to Purview > Data lifecycle management > Event types.",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check retention event types: {}", e);
                findings.push(
                    Finding::new(
                        "PURVIEW-RETENTION-004",
                        "Purview",
                        "Data Lifecycle",
                        "Retention Event Types",
                        "Failed to check retention event types",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("PURVIEW-RETENTION-004"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Event types should be accessible")
                    .build(),
                );
            }
        }

        // PURVIEW-RETENTION-005: Overall retention policy readiness
        let has_labels = findings
            .iter()
            .any(|f| f.check_id == "PURVIEW-RETENTION-001" && f.status == FindingStatus::Pass);
        let has_events = findings
            .iter()
            .any(|f| f.check_id == "PURVIEW-RETENTION-004" && f.status == FindingStatus::Pass);

        findings.push(
            Finding::new(
                "PURVIEW-RETENTION-005",
                "Purview",
                "Data Lifecycle",
                "Overall Retention Readiness",
                "Overall assessment of retention policy configuration maturity",
            )
            .status(if has_labels && has_events {
                FindingStatus::Pass
            } else if has_labels {
                FindingStatus::Warning
            } else {
                FindingStatus::Fail
            })
            .severity(registry.get_severity("PURVIEW-RETENTION-005"))
            .current_value(format!(
                "Retention labels: {}, Event types: {}",
                if has_labels { "Configured" } else { "Missing" },
                if has_events { "Configured" } else { "Not configured" },
            ))
            .expected_value("Both retention labels and event-based triggers should be configured")
            .remediation(
                "Implement a comprehensive data lifecycle management strategy using Microsoft Purview. Configure retention labels, publish label policies, and set up event-based retention for compliance requirements.",
            )
            .build(),
        );

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: serde_json::json!({}),
            error: None,
            duration_ms,
        })
    }
}
