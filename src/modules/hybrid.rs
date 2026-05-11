use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::assessment::severity::Severity;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct HybridModule;

#[async_trait]
impl AssessmentModule for HybridModule {
    fn name(&self) -> &str {
        "Hybrid"
    }

    fn description(&self) -> &str {
        "Checks Entra Connect hybrid identity synchronization health"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        _tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        // ENTRA-HYBRID-001: Check Entra Connect sync status
        match graph.get_json("/v1.0/organization").await {
            Ok(org_data) => {
                let org = org_data["value"].as_array().and_then(|a| a.first());

                if let Some(org_value) = org {
                    let sync_enabled = org_value["onPremisesSyncEnabled"]
                        .as_bool()
                        .unwrap_or(false);

                    if sync_enabled {
                        let last_sync = org_value["onPremisesLastSyncDateTime"]
                            .as_str()
                            .unwrap_or("");

                        let (status, description) = if last_sync.is_empty() {
                            (
                                FindingStatus::Review,
                                "Sync is enabled but no sync timestamp available - manual review required",
                            )
                        } else {
                            // Parse the timestamp and check sync freshness
                            match chrono::DateTime::parse_from_rfc3339(last_sync) {
                                Ok(sync_time) => {
                                    let now = chrono::Utc::now();
                                    let elapsed = now.signed_duration_since(
                                        sync_time.with_timezone(&chrono::Utc),
                                    );
                                    let hours_since = elapsed.num_hours();

                                    if hours_since <= 6 {
                                        (
                                            FindingStatus::Pass,
                                            "Entra Connect sync is healthy - last sync within 6 hours",
                                        )
                                    } else if hours_since <= 24 {
                                        (
                                            FindingStatus::Warning,
                                            "Entra Connect sync may be stale - last sync was more than 6 hours ago",
                                        )
                                    } else {
                                        (
                                            FindingStatus::Fail,
                                            "Entra Connect sync is stale - last sync was more than 24 hours ago",
                                        )
                                    }
                                }
                                Err(_) => (
                                    FindingStatus::Review,
                                    "Unable to parse last sync timestamp - manual review required",
                                ),
                            }
                        };

                        findings.push(
                            Finding::new(
                                "ENTRA-HYBRID-001",
                                "Hybrid Identity",
                                "Entra Connect",
                                "Directory Sync Status",
                                description,
                            )
                            .status(status)
                            .severity(registry.get_severity("ENTRA-HYBRID-001"))
                            .current_value(format!(
                                "Sync enabled: true, Last sync: {}",
                                if last_sync.is_empty() { "N/A" } else { last_sync }
                            ))
                            .expected_value("Sync should complete within the last 6 hours")
                            .remediation(
                                "If sync is stale, check the Entra Connect server health. Verify the synchronization service is running and the server has network connectivity to Azure AD.",
                            )
                            .build(),
                        );
                    } else {
                        // Sync not enabled - cloud-only tenant
                        findings.push(
                            Finding::new(
                                "ENTRA-HYBRID-001",
                                "Hybrid Identity",
                                "Entra Connect",
                                "Directory Sync Status",
                                "Cloud-only tenant, no sync configured",
                            )
                            .status(FindingStatus::Info)
                            .severity(Severity::Info)
                            .current_value("On-premises sync: Not enabled (cloud-only)")
                            .expected_value("Informational - no action needed for cloud-only tenants")
                            .remediation("No action needed. If hybrid identity is planned, configure Entra Connect.")
                            .build(),
                        );
                    }
                } else {
                    findings.push(
                        Finding::new(
                            "ENTRA-HYBRID-001",
                            "Hybrid Identity",
                            "Entra Connect",
                            "Directory Sync Status",
                            "Unable to retrieve organization data for sync status check",
                        )
                        .status(FindingStatus::Unknown)
                        .severity(registry.get_severity("ENTRA-HYBRID-001"))
                        .current_value("No organization data returned")
                        .expected_value("Organization data should be accessible")
                        .build(),
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Failed to check hybrid sync status: {}", e);
                findings.push(
                    Finding::new(
                        "ENTRA-HYBRID-001",
                        "Hybrid Identity",
                        "Entra Connect",
                        "Directory Sync Status",
                        "Failed to check Entra Connect sync status",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("ENTRA-HYBRID-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Sync status should be accessible")
                    .build(),
                );
            }
        }

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
