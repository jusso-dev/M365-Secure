use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct PowerBIModule;

/// Helper to create a Review finding for Power BI settings that require the PowerBI Management API
fn powerbi_review_finding(
    check_id: &str,
    section: &str,
    setting: &str,
    description: &str,
    expected: &str,
    remediation: &str,
    registry: &ControlRegistry,
) -> Finding {
    Finding::new(check_id, "Power BI", section, setting, description)
        .status(FindingStatus::Review)
        .severity(registry.get_severity(check_id))
        .current_value("Requires PowerBI Management API or Admin Portal review")
        .expected_value(expected)
        .remediation(remediation)
        .build()
}

#[async_trait]
impl AssessmentModule for PowerBIModule {
    fn name(&self) -> &str {
        "Power BI"
    }

    fn description(&self) -> &str {
        "Assesses Power BI tenant settings for security and compliance (CIS 9.x)"
    }

    #[allow(clippy::vec_init_then_push)]
    async fn run(
        &self,
        _graph: &GraphClient,
        _tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        // POWERBI-GUEST-001: Guest user access to content
        findings.push(powerbi_review_finding(
            "POWERBI-GUEST-001",
            "Guest Access",
            "Guest Access to Content",
            "CIS 9.1 - Ensure guest user access is restricted in Power BI",
            "Guest access should be limited to specific security groups or disabled",
            "Navigate to Power BI Admin Portal > Tenant settings > Export and sharing > Guest users can access Power BI. Restrict to specific security groups.",
            registry,
        ));

        // POWERBI-GUEST-002: Guest user editing and management
        findings.push(powerbi_review_finding(
            "POWERBI-GUEST-002",
            "Guest Access",
            "Guest Edit and Manage",
            "CIS 9.2 - Ensure guest users cannot edit and manage content",
            "Guest users should not be able to edit or manage content",
            "Navigate to Power BI Admin Portal > Tenant settings > Export and sharing > Allow guest users to edit and manage content. Set to Disabled.",
            registry,
        ));

        // POWERBI-GUEST-003: Guest user browsing
        findings.push(powerbi_review_finding(
            "POWERBI-GUEST-003",
            "Guest Access",
            "Guest Content Browsing",
            "CIS 9.3 - Ensure guest users cannot browse Power BI content",
            "Guest browsing should be disabled unless explicitly required",
            "Navigate to Power BI Admin Portal > Tenant settings > Export and sharing > Show Microsoft Entra guests in lists of suggested people. Set to Disabled.",
            registry,
        ));

        // POWERBI-SHARING-001: Share to external users
        findings.push(powerbi_review_finding(
            "POWERBI-SHARING-001",
            "External Sharing",
            "External User Sharing",
            "CIS 9.4 - Ensure external sharing of Power BI content is restricted",
            "External sharing should be limited to specific security groups",
            "Navigate to Power BI Admin Portal > Tenant settings > Export and sharing > Allow Microsoft Entra guest users to share to external. Restrict to specific security groups or disable.",
            registry,
        ));

        // POWERBI-SHARING-002: Publish to web
        findings.push(powerbi_review_finding(
            "POWERBI-SHARING-002",
            "External Sharing",
            "Publish to Web",
            "CIS 9.5 - Ensure Publish to Web is restricted",
            "Publish to Web should be disabled or restricted to specific groups",
            "Navigate to Power BI Admin Portal > Tenant settings > Export and sharing > Publish to web. Set to Disabled or restrict to specific security groups.",
            registry,
        ));

        // POWERBI-SHARING-003: Copy and paste visuals
        findings.push(powerbi_review_finding(
            "POWERBI-SHARING-003",
            "External Sharing",
            "Copy and Paste Visuals",
            "CIS 9.6 - Ensure interaction with external data sharing settings",
            "Copy and paste of visuals should be controlled to prevent data leakage",
            "Navigate to Power BI Admin Portal > Tenant settings > Export and sharing > Allow users to copy visuals as image and review settings.",
            registry,
        ));

        // POWERBI-SHARING-004: External data sharing
        findings.push(powerbi_review_finding(
            "POWERBI-SHARING-004",
            "External Sharing",
            "External Data Sharing",
            "CIS 9.7 - Ensure external data sharing controls are configured",
            "External data sharing should be restricted to approved scenarios",
            "Navigate to Power BI Admin Portal > Tenant settings > Export and sharing settings and review all external data sharing configurations.",
            registry,
        ));

        // POWERBI-INFOPROT-001: Sensitivity labels
        findings.push(powerbi_review_finding(
            "POWERBI-INFOPROT-001",
            "Information Protection",
            "Sensitivity Labels",
            "CIS 9.8 - Ensure sensitivity labels are enabled in Power BI",
            "Sensitivity labels should be enabled and applied to Power BI content",
            "Navigate to Power BI Admin Portal > Tenant settings > Information protection > Allow users to apply sensitivity labels. Set to Enabled.",
            registry,
        ));

        // POWERBI-AUTH-001: Service principal access
        findings.push(powerbi_review_finding(
            "POWERBI-AUTH-001",
            "Authentication",
            "Service Principal Access",
            "CIS 9.9 - Ensure service principal access is restricted",
            "Service principal access should be limited to specific security groups",
            "Navigate to Power BI Admin Portal > Tenant settings > Developer settings > Allow service principals to use Power BI APIs. Restrict to specific security groups.",
            registry,
        ));

        // POWERBI-AUTH-002: API access control
        findings.push(powerbi_review_finding(
            "POWERBI-AUTH-002",
            "Authentication",
            "API Access Control",
            "CIS 9.10 - Ensure API access is properly controlled",
            "API access should be limited and monitored",
            "Navigate to Power BI Admin Portal > Tenant settings > Developer settings and review API access configurations. Block unauthenticated access.",
            registry,
        ));

        // POWERBI-AUTH-003: Certification
        findings.push(powerbi_review_finding(
            "POWERBI-AUTH-003",
            "Authentication",
            "Content Certification",
            "CIS 9.11 - Ensure content certification is properly configured",
            "Content certification should be enabled with designated certifiers",
            "Navigate to Power BI Admin Portal > Tenant settings > Content pack and app settings > Certification. Enable and designate certifiers.",
            registry,
        ));

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
