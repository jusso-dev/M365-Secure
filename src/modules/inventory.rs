use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::assessment::severity::Severity;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct InventoryModule;

#[async_trait]
impl AssessmentModule for InventoryModule {
    fn name(&self) -> &str {
        "Inventory"
    }

    fn description(&self) -> &str {
        "Collects tenant resource inventory including users, groups, Teams, and SharePoint sites"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        _tenant: &TenantInfo,
        _registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let mut raw = serde_json::Map::new();

        // Mailbox / User inventory
        match graph
            .get_all::<serde_json::Value>(
                "/v1.0/users?$select=id,displayName,mail,userType&$top=999",
            )
            .await
        {
            Ok(users) => {
                let total_users = users.len();
                let member_count = users
                    .iter()
                    .filter(|u| u["userType"].as_str().unwrap_or("Member") == "Member")
                    .count();
                let guest_count = users
                    .iter()
                    .filter(|u| u["userType"].as_str().unwrap_or("") == "Guest")
                    .count();
                let with_mail = users
                    .iter()
                    .filter(|u| u["mail"].as_str().map(|m| !m.is_empty()).unwrap_or(false))
                    .count();

                raw.insert("user_count".to_string(), serde_json::json!(total_users));
                raw.insert("member_count".to_string(), serde_json::json!(member_count));
                raw.insert("guest_count".to_string(), serde_json::json!(guest_count));

                findings.push(
                    Finding::new(
                        "INV-USERS-001",
                        "Inventory",
                        "Users",
                        "User Inventory",
                        "Summary of user accounts in the tenant",
                    )
                    .status(FindingStatus::Info)
                    .severity(Severity::Info)
                    .current_value(format!(
                        "{} total users ({} members, {} guests, {} with mailboxes)",
                        total_users, member_count, guest_count, with_mail
                    ))
                    .expected_value("Informational")
                    .remediation(
                        "Review user inventory for stale accounts and excessive guest access",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to collect user inventory: {}", e);
                findings.push(
                    Finding::new(
                        "INV-USERS-001",
                        "Inventory",
                        "Users",
                        "User Inventory",
                        "Failed to collect user inventory",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(Severity::Info)
                    .current_value(format!("Error: {}", e))
                    .expected_value("Informational")
                    .build(),
                );
            }
        }

        // Group inventory
        match graph.get_all::<serde_json::Value>("/v1.0/groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled&$top=999").await {
            Ok(groups) => {
                let total_groups = groups.len();

                let m365_groups = groups
                    .iter()
                    .filter(|g| {
                        g["groupTypes"]
                            .as_array()
                            .map(|t| t.iter().any(|v| v.as_str() == Some("Unified")))
                            .unwrap_or(false)
                    })
                    .count();
                let security_groups = groups
                    .iter()
                    .filter(|g| {
                        g["securityEnabled"].as_bool().unwrap_or(false)
                            && !g["groupTypes"]
                                .as_array()
                                .map(|t| t.iter().any(|v| v.as_str() == Some("Unified")))
                                .unwrap_or(false)
                    })
                    .count();
                let distribution_groups = groups
                    .iter()
                    .filter(|g| {
                        g["mailEnabled"].as_bool().unwrap_or(false)
                            && !g["securityEnabled"].as_bool().unwrap_or(false)
                            && !g["groupTypes"]
                                .as_array()
                                .map(|t| t.iter().any(|v| v.as_str() == Some("Unified")))
                                .unwrap_or(false)
                    })
                    .count();

                raw.insert("group_count".to_string(), serde_json::json!(total_groups));
                raw.insert("m365_group_count".to_string(), serde_json::json!(m365_groups));
                raw.insert("security_group_count".to_string(), serde_json::json!(security_groups));

                findings.push(
                    Finding::new(
                        "INV-GROUPS-001",
                        "Inventory",
                        "Groups",
                        "Group Inventory",
                        "Summary of groups in the tenant by type",
                    )
                    .status(FindingStatus::Info)
                    .severity(Severity::Info)
                    .current_value(format!(
                        "{} total groups ({} M365, {} security, {} distribution)",
                        total_groups, m365_groups, security_groups, distribution_groups
                    ))
                    .expected_value("Informational")
                    .remediation("Review group inventory for unused groups and appropriate membership")
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to collect group inventory: {}", e);
                findings.push(
                    Finding::new(
                        "INV-GROUPS-001",
                        "Inventory",
                        "Groups",
                        "Group Inventory",
                        "Failed to collect group inventory",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(Severity::Info)
                    .current_value(format!("Error: {}", e))
                    .expected_value("Informational")
                    .build(),
                );
            }
        }

        // Teams inventory
        match graph.get_all::<serde_json::Value>(
            "/v1.0/groups?$filter=resourceProvisioningOptions/any(x:x eq 'Team')&$select=id,displayName,visibility&$top=999",
        ).await {
            Ok(teams) => {
                let total_teams = teams.len();
                let public_teams = teams
                    .iter()
                    .filter(|t| t["visibility"].as_str().unwrap_or("") == "Public")
                    .count();
                let private_teams = teams
                    .iter()
                    .filter(|t| t["visibility"].as_str().unwrap_or("") == "Private")
                    .count();

                raw.insert("teams_count".to_string(), serde_json::json!(total_teams));

                findings.push(
                    Finding::new(
                        "INV-TEAMS-001",
                        "Inventory",
                        "Teams",
                        "Teams Inventory",
                        "Summary of Microsoft Teams in the tenant",
                    )
                    .status(FindingStatus::Info)
                    .severity(Severity::Info)
                    .current_value(format!(
                        "{} teams ({} public, {} private)",
                        total_teams, public_teams, private_teams
                    ))
                    .expected_value("Informational")
                    .remediation("Review Teams inventory for proper governance and access controls")
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to collect Teams inventory: {}", e);
                findings.push(
                    Finding::new(
                        "INV-TEAMS-001",
                        "Inventory",
                        "Teams",
                        "Teams Inventory",
                        "Failed to collect Teams inventory",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(Severity::Info)
                    .current_value(format!("Error: {}", e))
                    .expected_value("Informational")
                    .build(),
                );
            }
        }

        // SharePoint site inventory
        match graph
            .get_all::<serde_json::Value>("/v1.0/sites?$select=id,displayName,webUrl&$top=999")
            .await
        {
            Ok(sites) => {
                let total_sites = sites.len();
                raw.insert("site_count".to_string(), serde_json::json!(total_sites));

                findings.push(
                    Finding::new(
                        "INV-SITES-001",
                        "Inventory",
                        "SharePoint",
                        "SharePoint Site Inventory",
                        "Summary of SharePoint sites in the tenant",
                    )
                    .status(FindingStatus::Info)
                    .severity(Severity::Info)
                    .current_value(format!("{} SharePoint sites", total_sites))
                    .expected_value("Informational")
                    .remediation("Review SharePoint site inventory for proper governance and sharing settings")
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to collect SharePoint inventory: {}", e);
                findings.push(
                    Finding::new(
                        "INV-SITES-001",
                        "Inventory",
                        "SharePoint",
                        "SharePoint Site Inventory",
                        "Failed to collect SharePoint site inventory",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(Severity::Info)
                    .current_value(format!("Error: {}", e))
                    .expected_value("Informational")
                    .build(),
                );
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: serde_json::Value::Object(raw),
            error: None,
            duration_ms,
        })
    }
}
