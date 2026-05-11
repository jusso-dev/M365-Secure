use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::assessment::severity::Severity;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct ValueOpportunityModule;

/// Features typically included in E3/E5 that can be checked for adoption
const FEATURE_CHECKS: &[(&str, &str, &str, &str)] = &[
    (
        "Conditional Access",
        "AAD_PREMIUM",
        "/v1.0/identity/conditionalAccess/policies",
        "Entra ID P1/P2",
    ),
    (
        "PIM",
        "AAD_PREMIUM_P2",
        "/beta/privilegedAccess/aadroles/resources",
        "Entra ID P2",
    ),
    (
        "Intune MDM",
        "INTUNE_A",
        "/beta/deviceManagement/managedDevices",
        "Intune",
    ),
    (
        "Information Protection",
        "INFORMATION_PROTECTION_COMPLIANCE",
        "/beta/security/labels/retentionLabels",
        "Purview / E5",
    ),
];

#[async_trait]
impl AssessmentModule for ValueOpportunityModule {
    fn name(&self) -> &str {
        "Value Opportunity"
    }

    fn description(&self) -> &str {
        "Analyzes license utilization, feature adoption, and readiness for advanced security features"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        _registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let mut raw = serde_json::Map::new();

        // --- License Utilization Analysis ---
        let mut underutilized_skus = Vec::new();
        let mut overallocated_skus = Vec::new();

        for sku in &tenant.license_skus {
            if sku.prepaid_units == 0 {
                continue;
            }

            let utilization = (sku.consumed_units as f64 / sku.prepaid_units as f64) * 100.0;

            if utilization < 50.0 {
                underutilized_skus.push(format!(
                    "{} ({:.0}% used, {} of {} seats)",
                    sku.sku_part_number, utilization, sku.consumed_units, sku.prepaid_units
                ));
            }
            if sku.consumed_units > sku.prepaid_units {
                overallocated_skus.push(format!(
                    "{} ({} consumed vs {} available)",
                    sku.sku_part_number, sku.consumed_units, sku.prepaid_units
                ));
            }
        }

        findings.push(
            Finding::new(
                "VALUE-UTIL-001",
                "Value Opportunity",
                "License Utilization",
                "Under-Utilized Licenses",
                "Identifies license SKUs with less than 50% utilization - potential cost savings",
            )
            .status(FindingStatus::Info)
            .severity(Severity::Info)
            .current_value(if underutilized_skus.is_empty() {
                "No significantly under-utilized SKUs found".to_string()
            } else {
                format!("{} under-utilized SKUs: {}", underutilized_skus.len(), underutilized_skus.join("; "))
            })
            .expected_value("All licensed seats should be assigned and actively used")
            .remediation(
                "Review under-utilized licenses. Consider reducing seat counts at renewal or reassigning unused licenses to maximize ROI.",
            )
            .build(),
        );

        if !overallocated_skus.is_empty() {
            findings.push(
                Finding::new(
                    "VALUE-UTIL-002",
                    "Value Opportunity",
                    "License Utilization",
                    "Over-Allocated Licenses",
                    "Identifies SKUs where consumed seats exceed available seats",
                )
                .status(FindingStatus::Warning)
                .severity(Severity::Low)
                .current_value(format!(
                    "{} over-allocated SKUs: {}",
                    overallocated_skus.len(),
                    overallocated_skus.join("; ")
                ))
                .expected_value("Consumed units should not exceed prepaid units")
                .remediation(
                    "Purchase additional licenses to cover over-allocation, or remove license assignments from inactive users.",
                )
                .build(),
            );
        }

        // --- Feature Adoption Signals ---
        let mut adopted_features = Vec::new();
        let mut not_adopted_features = Vec::new();
        let mut not_licensed_features = Vec::new();

        for (feature_name, service_plan, api_endpoint, license_tier) in FEATURE_CHECKS {
            let is_licensed = tenant.has_service_plan(service_plan);

            if is_licensed {
                match graph.get_json(api_endpoint).await {
                    Ok(data) => {
                        let has_data = data["value"]
                            .as_array()
                            .map(|a| !a.is_empty())
                            .unwrap_or(false);

                        if has_data {
                            adopted_features.push(feature_name.to_string());
                        } else {
                            not_adopted_features
                                .push(format!("{} (licensed via {})", feature_name, license_tier));
                        }
                    }
                    Err(_) => {
                        // API error doesn't necessarily mean not adopted
                        adopted_features.push(format!("{} (unable to verify)", feature_name));
                    }
                }
            } else {
                not_licensed_features.push(format!("{} (requires {})", feature_name, license_tier));
            }
        }

        findings.push(
            Finding::new(
                "VALUE-ADOPT-001",
                "Value Opportunity",
                "Feature Adoption",
                "Security Feature Adoption",
                "Identifies which licensed security features are actively in use",
            )
            .status(FindingStatus::Info)
            .severity(Severity::Info)
            .current_value(format!(
                "{} features adopted: {}",
                adopted_features.len(),
                if adopted_features.is_empty() {
                    "None detected".to_string()
                } else {
                    adopted_features.join(", ")
                }
            ))
            .expected_value("All licensed security features should be enabled and configured")
            .remediation(
                "Enable and configure all security features included in your current licensing. This maximizes return on your M365 investment.",
            )
            .build(),
        );

        // --- Feature Readiness Assessment (licensed but not deployed) ---
        if !not_adopted_features.is_empty() {
            findings.push(
                Finding::new(
                    "VALUE-READY-001",
                    "Value Opportunity",
                    "Feature Readiness",
                    "Licensed But Not Deployed",
                    "Features included in current licensing that are not yet deployed",
                )
                .status(FindingStatus::Warning)
                .severity(Severity::Low)
                .current_value(format!(
                    "{} features licensed but not deployed: {}",
                    not_adopted_features.len(),
                    not_adopted_features.join("; ")
                ))
                .expected_value("Licensed features should be deployed to maximize security posture and ROI")
                .remediation(
                    "Deploy these already-licensed features to improve security at no additional cost. Prioritize Conditional Access, MFA, and endpoint management.",
                )
                .build(),
            );
        }

        // Not-licensed features as upgrade opportunities
        if !not_licensed_features.is_empty() {
            findings.push(
                Finding::new(
                    "VALUE-READY-002",
                    "Value Opportunity",
                    "Feature Readiness",
                    "Upgrade Opportunities",
                    "Security features available via license upgrades",
                )
                .status(FindingStatus::Info)
                .severity(Severity::Info)
                .current_value(format!(
                    "{} features available with license upgrades: {}",
                    not_licensed_features.len(),
                    not_licensed_features.join("; ")
                ))
                .expected_value("Informational - consider based on security requirements")
                .remediation(
                    "Evaluate these features against your security requirements. Microsoft 365 E5 or add-on licenses provide the most comprehensive security coverage.",
                )
                .build(),
            );
        }

        raw.insert(
            "adopted_features".to_string(),
            serde_json::json!(adopted_features),
        );
        raw.insert(
            "not_adopted_features".to_string(),
            serde_json::json!(not_adopted_features),
        );
        raw.insert(
            "underutilized_skus".to_string(),
            serde_json::json!(underutilized_skus),
        );

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
