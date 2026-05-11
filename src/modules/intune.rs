use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::assessment::severity::Severity;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct IntuneModule;

#[async_trait]
impl AssessmentModule for IntuneModule {
    fn name(&self) -> &str {
        "Intune"
    }

    fn description(&self) -> &str {
        "Assesses Microsoft Intune device management configuration and compliance"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        _tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        // INTUNE-COMPLIANCE-001: Compliance policies
        match graph
            .get_json("/beta/deviceManagement/compliancePolicies")
            .await
        {
            Ok(data) => {
                let policy_list = data["value"].as_array();
                let policies = policy_list.map(|a| a.len()).unwrap_or(0);

                // Check if any policy has assignments (is actually deployed)
                let assigned_count = policy_list
                    .map(|arr| {
                        arr.iter()
                            .filter(|p| {
                                p["assignments"]
                                    .as_array()
                                    .map(|a| !a.is_empty())
                                    .unwrap_or(false)
                            })
                            .count()
                    })
                    .unwrap_or(0);

                let (status, current) = if policies == 0 {
                    (
                        FindingStatus::Fail,
                        "No compliance policies configured".to_string(),
                    )
                } else if assigned_count == 0 {
                    (
                        FindingStatus::Warning,
                        format!(
                            "{} compliance policies configured but none are assigned to users/devices",
                            policies
                        ),
                    )
                } else {
                    (
                        FindingStatus::Pass,
                        format!(
                            "{} compliance policies configured, {} assigned",
                            policies, assigned_count
                        ),
                    )
                };

                findings.push(
                    Finding::new(
                        "INTUNE-COMPLIANCE-001",
                        "Intune",
                        "Device Compliance",
                        "Compliance Policies",
                        "Check that device compliance policies are configured and assigned in Intune",
                    )
                    .status(status)
                    .severity(registry.get_severity("INTUNE-COMPLIANCE-001"))
                    .current_value(current)
                    .expected_value("At least 1 compliance policy configured and assigned")
                    .remediation(
                        "Configure compliance policies in Intune and assign them to user or device groups. Navigate to Endpoint Manager > Devices > Compliance policies.",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check compliance policies: {}", e);
                findings.push(
                    Finding::new(
                        "INTUNE-COMPLIANCE-001",
                        "Intune",
                        "Device Compliance",
                        "Compliance Policies",
                        "Check that device compliance policies are configured in Intune",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("INTUNE-COMPLIANCE-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("At least 1 compliance policy configured")
                    .build(),
                );
            }
        }

        // INTUNE-ENROLL-001: Enrollment restrictions
        match graph
            .get_json("/beta/deviceManagement/deviceEnrollmentConfigurations")
            .await
        {
            Ok(data) => {
                let config_list = data["value"].as_array();
                let configs = config_list.map(|a| a.len()).unwrap_or(0);

                // Default enrollment configs always exist; check for custom ones
                let custom_count = config_list
                    .map(|arr| {
                        arr.iter()
                            .filter(|c| {
                                // Default configs have priority 0 or are marked as default
                                let priority = c["priority"].as_i64().unwrap_or(0);
                                let is_default = c["displayName"]
                                    .as_str()
                                    .map(|n| n.contains("Default") || n.contains("All users"))
                                    .unwrap_or(false);
                                priority > 0 || !is_default
                            })
                            .count()
                    })
                    .unwrap_or(0);

                let status = if custom_count > 0 {
                    FindingStatus::Pass
                } else {
                    FindingStatus::Fail
                };
                findings.push(
                    Finding::new(
                        "INTUNE-ENROLL-001",
                        "Intune",
                        "Device Enrollment",
                        "Enrollment Restrictions",
                        "Check that device enrollment restrictions are configured beyond defaults",
                    )
                    .status(status)
                    .severity(registry.get_severity("INTUNE-ENROLL-001"))
                    .current_value(format!(
                        "{} total enrollment configurations, {} custom",
                        configs, custom_count
                    ))
                    .expected_value("At least 1 custom enrollment restriction should be configured")
                    .remediation(
                        "Configure enrollment restrictions to limit which platforms and device types can enroll. Navigate to Endpoint Manager > Devices > Enrollment restrictions.",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check enrollment restrictions: {}", e);
                findings.push(
                    Finding::new(
                        "INTUNE-ENROLL-001",
                        "Intune",
                        "Device Enrollment",
                        "Enrollment Restrictions",
                        "Check that device enrollment restrictions are configured",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("INTUNE-ENROLL-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Enrollment restrictions should be configured")
                    .build(),
                );
            }
        }

        // Device configuration profiles
        match graph
            .get_json("/beta/deviceManagement/deviceConfigurations")
            .await
        {
            Ok(data) => {
                let profiles = data["value"].as_array().map(|a| a.len()).unwrap_or(0);
                findings.push(
                    Finding::new(
                        "INTUNE-CONFIG-001",
                        "Intune",
                        "Device Configuration",
                        "Configuration Profiles",
                        "Inventory of device configuration profiles",
                    )
                    .status(if profiles > 0 { FindingStatus::Info } else { FindingStatus::Warning })
                    .severity(registry.get_severity("INTUNE-CONFIG-001"))
                    .current_value(format!("{} configuration profiles", profiles))
                    .expected_value("Configuration profiles should be deployed for managed devices")
                    .remediation(
                        "Create device configuration profiles to enforce security settings. Navigate to Endpoint Manager > Devices > Configuration profiles.",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check device configurations: {}", e);
            }
        }

        // Settings catalog policies
        match graph
            .get_json("/beta/deviceManagement/configurationPolicies")
            .await
        {
            Ok(data) => {
                let policies = data["value"].as_array().map(|a| a.len()).unwrap_or(0);
                findings.push(
                    Finding::new(
                        "INTUNE-SETTINGS-001",
                        "Intune",
                        "Device Configuration",
                        "Settings Catalog Policies",
                        "Inventory of Settings Catalog configuration policies",
                    )
                    .status(FindingStatus::Info)
                    .severity(Severity::Info)
                    .current_value(format!("{} settings catalog policies", policies))
                    .expected_value("Informational")
                    .remediation(
                        "Settings Catalog provides granular device configuration. Navigate to Endpoint Manager > Devices > Configuration profiles > Create > Settings catalog.",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check settings catalog policies: {}", e);
            }
        }

        // Managed devices summary
        match graph
            .get_json("/beta/deviceManagement/managedDevices")
            .await
        {
            Ok(data) => {
                let devices = data["value"].as_array().map(|a| a.len()).unwrap_or(0);
                findings.push(
                    Finding::new(
                        "INTUNE-DEVICES-001",
                        "Intune",
                        "Managed Devices",
                        "Device Inventory",
                        "Summary of devices managed by Intune",
                    )
                    .status(FindingStatus::Info)
                    .severity(Severity::Info)
                    .current_value(format!("{} managed devices", devices))
                    .expected_value("Informational")
                    .remediation("Ensure all corporate devices are enrolled in Intune management")
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check managed devices: {}", e);
            }
        }

        // INTUNE-MULTIAPPROVAL-001: Multi-admin approval
        match graph
            .get_json("/beta/deviceManagement/operationApprovalPolicies")
            .await
        {
            Ok(data) => {
                let policies = data["value"].as_array().map(|a| a.len()).unwrap_or(0);
                let status = if policies > 0 {
                    FindingStatus::Pass
                } else {
                    FindingStatus::Fail
                };
                findings.push(
                    Finding::new(
                        "INTUNE-MULTIAPPROVAL-001",
                        "Intune",
                        "Admin Security",
                        "Multi-Admin Approval",
                        "Check that multi-admin approval is configured for sensitive operations",
                    )
                    .status(status)
                    .severity(registry.get_severity("INTUNE-MULTIAPPROVAL-001"))
                    .current_value(format!("{} approval policies configured", policies))
                    .expected_value("At least 1 multi-admin approval policy should be configured")
                    .remediation(
                        "Enable multi-admin approval to require multiple administrators to approve critical operations like device wipes. Navigate to Endpoint Manager > Tenant administration > Multi-admin approval.",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check multi-admin approval: {}", e);
                findings.push(
                    Finding::new(
                        "INTUNE-MULTIAPPROVAL-001",
                        "Intune",
                        "Admin Security",
                        "Multi-Admin Approval",
                        "Check that multi-admin approval is configured for sensitive operations",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("INTUNE-MULTIAPPROVAL-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("At least 1 multi-admin approval policy should be configured")
                    .build(),
                );
            }
        }

        // INTUNE-SCOPETAGS-001: RBAC scope tags
        match graph.get_json("/beta/deviceManagement/roleScopeTags").await {
            Ok(data) => {
                let tags = data["value"].as_array().map(|a| a.len()).unwrap_or(0);
                // Default scope tag always exists, so > 1 means custom tags configured
                let status = if tags > 1 {
                    FindingStatus::Pass
                } else {
                    FindingStatus::Warning
                };
                findings.push(
                    Finding::new(
                        "INTUNE-SCOPETAGS-001",
                        "Intune",
                        "RBAC",
                        "Scope Tags",
                        "Check that RBAC scope tags are used to segment management",
                    )
                    .status(status)
                    .severity(registry.get_severity("INTUNE-SCOPETAGS-001"))
                    .current_value(format!("{} scope tags configured (including default)", tags))
                    .expected_value("Custom scope tags should be configured for delegated administration")
                    .remediation(
                        "Configure scope tags to limit administrator visibility and control. Navigate to Endpoint Manager > Tenant administration > Roles > Scope tags.",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check scope tags: {}", e);
                findings.push(
                    Finding::new(
                        "INTUNE-SCOPETAGS-001",
                        "Intune",
                        "RBAC",
                        "Scope Tags",
                        "Check that RBAC scope tags are used to segment management",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("INTUNE-SCOPETAGS-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Custom scope tags should be configured")
                    .build(),
                );
            }
        }

        // INTUNE-WIPAUDIT-001: Device wipe audit
        match graph
            .get_json("/beta/deviceManagement/auditEvents?$top=50&$filter=activityType eq 'Wipe'")
            .await
        {
            Ok(data) => {
                let events = data["value"].as_array().map(|a| a.len()).unwrap_or(0);
                let status = if events == 0 {
                    FindingStatus::Pass
                } else {
                    FindingStatus::Warning
                };
                findings.push(
                    Finding::new(
                        "INTUNE-WIPAUDIT-001",
                        "Intune",
                        "Audit",
                        "Device Wipe Audit",
                        "Audit recent device wipe operations for unauthorized activity",
                    )
                    .status(status)
                    .severity(registry.get_severity("INTUNE-WIPAUDIT-001"))
                    .current_value(format!("{} recent wipe events found", events))
                    .expected_value("Review any wipe events to confirm they were authorized")
                    .remediation(
                        "Review device wipe audit events to ensure all wipe operations were authorized. Enable multi-admin approval for wipe operations.",
                    )
                    .build(),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to check wipe audit events: {}", e);
                findings.push(
                    Finding::new(
                        "INTUNE-WIPAUDIT-001",
                        "Intune",
                        "Audit",
                        "Device Wipe Audit",
                        "Audit recent device wipe operations",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("INTUNE-WIPAUDIT-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Wipe events should be auditable")
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
