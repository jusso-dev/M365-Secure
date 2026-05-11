use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::assessment::severity::Severity;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct LicensingModule;

/// Key SKU identifiers for Microsoft 365 license tiers
const KEY_SKU_PATTERNS: &[(&str, &str)] = &[
    ("SPE_E5", "Microsoft 365 E5"),
    ("SPE_E3", "Microsoft 365 E3"),
    ("ENTERPRISEPACK", "Office 365 E3"),
    ("ENTERPRISEPREMIUM", "Office 365 E5"),
    ("AAD_PREMIUM_P2", "Entra ID P2"),
    ("AAD_PREMIUM", "Entra ID P1"),
    ("EMSPREMIUM", "EMS E5"),
    ("EMS", "EMS E3"),
    ("FLOW_FREE", "Power Automate Free"),
    ("POWER_BI_STANDARD", "Power BI Free"),
    ("POWER_BI_PRO", "Power BI Pro"),
    ("STREAM", "Microsoft Stream"),
    ("PROJECTPREMIUM", "Project Plan 5"),
    ("VISIOCLIENT", "Visio Plan 2"),
    ("MCOEV", "Teams Phone System"),
    ("WIN_DEF_ATP", "Defender for Endpoint P2"),
    ("THREAT_INTELLIGENCE", "Defender for Office 365 P2"),
    ("ATP_ENTERPRISE", "Defender for Office 365 P1"),
    ("INTUNE_A", "Microsoft Intune"),
    ("IDENTITY_THREAT_PROTECTION", "Entra ID Protection"),
];

fn identify_sku(sku_part: &str) -> Option<&'static str> {
    for (pattern, label) in KEY_SKU_PATTERNS {
        if sku_part.to_uppercase().contains(pattern) {
            return Some(label);
        }
    }
    None
}

#[async_trait]
impl AssessmentModule for LicensingModule {
    fn name(&self) -> &str {
        "Licensing"
    }

    fn description(&self) -> &str {
        "Analyzes Microsoft 365 license allocation and utilization"
    }

    async fn run(
        &self,
        _graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        // Summary finding: total SKUs
        let total_skus = tenant.license_skus.len();
        let total_consumed: u32 = tenant.license_skus.iter().map(|s| s.consumed_units).sum();
        let total_available: u32 = tenant.license_skus.iter().map(|s| s.prepaid_units).sum();

        findings.push(
            Finding::new(
                "LIC-SUMMARY-001",
                "Licensing",
                "License Overview",
                "Total License SKUs",
                "Summary of all subscribed license SKUs in the tenant",
            )
            .status(FindingStatus::Info)
            .severity(Severity::Info)
            .current_value(format!(
                "{} SKUs, {} consumed of {} total seats",
                total_skus, total_consumed, total_available
            ))
            .expected_value("Informational")
            .remediation("Review license allocation to ensure optimal utilization")
            .build(),
        );

        // Per-SKU findings
        for sku in &tenant.license_skus {
            let friendly_name = identify_sku(&sku.sku_part_number).unwrap_or("Unknown SKU");

            let utilization = if sku.prepaid_units > 0 {
                (sku.consumed_units as f64 / sku.prepaid_units as f64) * 100.0
            } else {
                0.0
            };

            let check_id = format!(
                "LIC-SKU-{}",
                sku.sku_part_number.to_uppercase().replace(' ', "_")
            );

            let status = if sku.consumed_units > sku.prepaid_units && sku.prepaid_units > 0 {
                FindingStatus::Warning
            } else {
                FindingStatus::Info
            };

            let severity_val = registry.get_severity(&check_id);

            findings.push(
                Finding::new(
                    &check_id,
                    "Licensing",
                    "License Allocation",
                    format!("{} ({})", friendly_name, sku.sku_part_number),
                    format!(
                        "License allocation for {} - {:.0}% utilized",
                        friendly_name, utilization
                    ),
                )
                .status(status)
                .severity(severity_val)
                .current_value(format!(
                    "{} consumed / {} available ({:.0}%)",
                    sku.consumed_units, sku.prepaid_units, utilization
                ))
                .expected_value("Informational - review for optimal allocation")
                .remediation(
                    if sku.consumed_units > sku.prepaid_units && sku.prepaid_units > 0 {
                        "Over-allocated: consider purchasing additional licenses or removing unused assignments"
                    } else if utilization < 50.0 && sku.prepaid_units > 0 {
                        "Under-utilized: consider reducing license count or assigning to more users"
                    } else {
                        "No action needed"
                    },
                )
                .build(),
            );
        }

        // Key SKU identification
        let has_e5 = tenant.has_e5();
        let has_p2 = tenant.has_p2();

        let (tier_status, tier_description, tier_note) = if has_e5 || has_p2 {
            (
                FindingStatus::Info,
                "Premium security licenses detected",
                "Premium licenses detected - ensure all included security features are enabled",
            )
        } else {
            (
                FindingStatus::Info,
                "No E5 or Entra ID P2 licenses detected - premium features such as Conditional Access, PIM, Identity Protection, and advanced threat protection will not be available",
                "Consider Microsoft 365 E5 or Entra ID P2 for advanced security features including Conditional Access, PIM, and Identity Protection",
            )
        };

        findings.push(
            Finding::new(
                "LIC-TIER-001",
                "Licensing",
                "License Tier",
                "Premium License Detection",
                tier_description,
            )
            .status(tier_status)
            .severity(Severity::Info)
            .current_value(format!(
                "E5: {}, Entra ID P2: {}",
                if has_e5 { "Yes" } else { "No" },
                if has_p2 { "Yes" } else { "No" },
            ))
            .expected_value("Informational")
            .remediation(tier_note)
            .build(),
        );

        // LIC-OVERALLOC-001: License over-allocation check
        let overallocated_skus: Vec<String> = tenant
            .license_skus
            .iter()
            .filter(|sku| sku.prepaid_units > 0 && sku.consumed_units > sku.prepaid_units)
            .map(|sku| {
                let friendly = identify_sku(&sku.sku_part_number).unwrap_or("Unknown SKU");
                format!(
                    "{} ({}) - {} consumed / {} available",
                    friendly, sku.sku_part_number, sku.consumed_units, sku.prepaid_units
                )
            })
            .collect();

        let (overalloc_status, overalloc_current) = if overallocated_skus.is_empty() {
            (
                FindingStatus::Pass,
                "No over-allocated SKUs detected".to_string(),
            )
        } else {
            (
                FindingStatus::Warning,
                format!(
                    "{} over-allocated SKU(s): {}",
                    overallocated_skus.len(),
                    overallocated_skus.join("; ")
                ),
            )
        };

        findings.push(
            Finding::new(
                "LIC-OVERALLOC-001",
                "Licensing",
                "License Allocation",
                "License Over-Allocation",
                "Check for SKUs where consumed licenses exceed prepaid seats",
            )
            .status(overalloc_status)
            .severity(registry.get_severity("LIC-OVERALLOC-001"))
            .current_value(overalloc_current)
            .expected_value("No SKUs should have consumed units exceeding prepaid units")
            .remediation(
                "Purchase additional licenses or remove unused assignments to resolve over-allocation. Over-allocated licenses may result in service disruption.",
            )
            .build(),
        );

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: serde_json::json!({
                "total_skus": total_skus,
                "total_consumed": total_consumed,
                "total_available": total_available,
                "has_e5": has_e5,
                "has_p2": has_p2,
            }),
            error: None,
            duration_ms,
        })
    }
}
