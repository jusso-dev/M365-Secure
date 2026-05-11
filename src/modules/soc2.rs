use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus, FrameworkMappings};
use crate::assessment::registry::ControlRegistry;
use crate::assessment::severity::Severity;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct SOC2Module;

#[async_trait]
impl AssessmentModule for SOC2Module {
    fn name(&self) -> &str {
        "SOC 2"
    }

    fn description(&self) -> &str {
        "Maps Microsoft 365 security controls to SOC 2 Trust Services Criteria"
    }

    #[allow(clippy::vec_init_then_push)]
    async fn run(
        &self,
        graph: &GraphClient,
        _tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        // --- SOC 2 Security Controls (CC6: Logical and Physical Access) ---
        findings.push(
            Finding::new(
                "SOC2-CC6-001",
                "SOC 2",
                "CC6 - Logical Access",
                "User Authentication Controls",
                "CC6.1 - Logical access security controls for user authentication",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("SOC2-CC6-001"))
            .current_value("Mapped from Identity module assessments (MFA, Conditional Access)")
            .expected_value("MFA enforced for all users, Conditional Access policies configured")
            .remediation(
                "Review Identity module findings for ENTRA-MFA and ENTRA-CA checks. Ensure MFA is enforced and Conditional Access policies cover all user scenarios.",
            )
            .mappings(FrameworkMappings {
                soc2: vec!["CC6.1".to_string(), "CC6.2".to_string()],
                ..Default::default()
            })
            .build(),
        );

        findings.push(
            Finding::new(
                "SOC2-CC6-002",
                "SOC 2",
                "CC6 - Logical Access",
                "Privileged Access Management",
                "CC6.3 - Controls over privileged access and administrative accounts",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("SOC2-CC6-002"))
            .current_value("Mapped from Identity module (PIM, admin role assignments)")
            .expected_value("PIM enabled, just-in-time access for privileged roles, limited permanent admins")
            .remediation(
                "Review Identity module findings for ENTRA-PIM and ENTRA-ADMIN checks. Ensure privileged access uses PIM with time-limited role assignments.",
            )
            .mappings(FrameworkMappings {
                soc2: vec!["CC6.3".to_string()],
                ..Default::default()
            })
            .build(),
        );

        // --- SOC 2 Security Controls (CC7: System Operations) ---
        findings.push(
            Finding::new(
                "SOC2-CC7-001",
                "SOC 2",
                "CC7 - System Operations",
                "Threat Detection and Monitoring",
                "CC7.2 - Monitoring of system components for anomalies and security events",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("SOC2-CC7-001"))
            .current_value("Mapped from Security module (Defender, alert policies)")
            .expected_value("Microsoft Defender enabled, alert policies configured, security monitoring active")
            .remediation(
                "Review Security module findings for Defender configuration. Ensure threat detection, alert policies, and incident response procedures are in place.",
            )
            .mappings(FrameworkMappings {
                soc2: vec!["CC7.2".to_string(), "CC7.3".to_string()],
                ..Default::default()
            })
            .build(),
        );

        findings.push(
            Finding::new(
                "SOC2-CC7-002",
                "SOC 2",
                "CC7 - System Operations",
                "Incident Response",
                "CC7.4 - Incident response procedures and notification",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("SOC2-CC7-002"))
            .current_value("Requires manual review of incident response plan")
            .expected_value("Documented incident response plan with defined roles and communication procedures")
            .remediation(
                "Document an incident response plan that covers detection, analysis, containment, eradication, and recovery. Test the plan regularly.",
            )
            .mappings(FrameworkMappings {
                soc2: vec!["CC7.4".to_string(), "CC7.5".to_string()],
                ..Default::default()
            })
            .build(),
        );

        // --- SOC 2 Security Controls (CC8: Change Management) ---
        findings.push(
            Finding::new(
                "SOC2-CC8-001",
                "SOC 2",
                "CC8 - Change Management",
                "Change Management Process",
                "CC8.1 - Changes to infrastructure and software are authorized and managed",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("SOC2-CC8-001"))
            .current_value("Requires manual review of change management processes")
            .expected_value("Documented change management process with approval workflows")
            .remediation(
                "Implement formal change management procedures. Use Intune multi-admin approval for device management changes. Document approval processes for infrastructure modifications.",
            )
            .mappings(FrameworkMappings {
                soc2: vec!["CC8.1".to_string()],
                ..Default::default()
            })
            .build(),
        );

        // --- SOC 2 Security Controls (CC9: Risk Mitigation) ---
        findings.push(
            Finding::new(
                "SOC2-CC9-001",
                "SOC 2",
                "CC9 - Risk Mitigation",
                "Vendor and Third-Party Risk",
                "CC9.2 - Risk assessment and management of third-party service providers",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("SOC2-CC9-001"))
            .current_value("Requires manual review of vendor risk management program")
            .expected_value("Vendor risk assessment process documented, third-party app consent policies configured")
            .remediation(
                "Review Entra ID app registrations and enterprise applications. Implement an admin consent workflow and restrict user consent for third-party apps.",
            )
            .mappings(FrameworkMappings {
                soc2: vec!["CC9.2".to_string()],
                ..Default::default()
            })
            .build(),
        );

        // --- SOC 2 Confidentiality Controls (C1, C2) ---
        findings.push(
            Finding::new(
                "SOC2-C1-001",
                "SOC 2",
                "C1 - Confidentiality",
                "Data Classification",
                "C1.1 - Confidential information is identified and classified",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("SOC2-C1-001"))
            .current_value("Mapped from Purview module (sensitivity labels, DLP policies)")
            .expected_value("Sensitivity labels configured and published, DLP policies protecting confidential data")
            .remediation(
                "Configure Microsoft Purview sensitivity labels for data classification. Create DLP policies to prevent unauthorized sharing of confidential data.",
            )
            .mappings(FrameworkMappings {
                soc2: vec!["C1.1".to_string(), "C1.2".to_string()],
                ..Default::default()
            })
            .build(),
        );

        findings.push(
            Finding::new(
                "SOC2-C2-001",
                "SOC 2",
                "C2 - Confidentiality",
                "Data Disposal",
                "C2.1 - Confidential information is disposed of securely",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("SOC2-C2-001"))
            .current_value("Mapped from Purview module (retention policies and labels)")
            .expected_value("Retention policies configured with appropriate disposal actions")
            .remediation(
                "Configure retention labels with disposal actions in Microsoft Purview. Implement disposition review workflows for regulated content.",
            )
            .mappings(FrameworkMappings {
                soc2: vec!["C2.1".to_string()],
                ..Default::default()
            })
            .build(),
        );

        // --- SOC 2 Audit Evidence: 30-day audit log ---
        match graph.get_json("/beta/security/auditLog/queries").await {
            Ok(_data) => {
                findings.push(
                    Finding::new(
                        "SOC2-AUDIT-001",
                        "SOC 2",
                        "Audit Evidence",
                        "Unified Audit Log",
                        "Verify that unified audit logging is enabled and accessible",
                    )
                    .status(FindingStatus::Pass)
                    .severity(registry.get_severity("SOC2-AUDIT-001"))
                    .current_value("Audit log API is accessible")
                    .expected_value("Unified audit log enabled with at least 30 days retention")
                    .remediation(
                        "Ensure unified audit log is enabled in Microsoft Purview. E5 licenses provide 1-year default retention; E3 provides 180 days.",
                    )
                    .mappings(FrameworkMappings {
                        soc2: vec!["CC7.2".to_string()],
                        ..Default::default()
                    })
                    .build(),
                );
            }
            Err(_e) => {
                // Try alternative endpoint
                match graph
                    .get_json("/v1.0/auditLogs/directoryAudits?$top=1")
                    .await
                {
                    Ok(_) => {
                        findings.push(
                            Finding::new(
                                "SOC2-AUDIT-001",
                                "SOC 2",
                                "Audit Evidence",
                                "Unified Audit Log",
                                "Audit logging is available via directory audit logs",
                            )
                            .status(FindingStatus::Pass)
                            .severity(registry.get_severity("SOC2-AUDIT-001"))
                            .current_value("Directory audit logs are accessible")
                            .expected_value("Audit logging enabled with at least 30 days retention")
                            .remediation(
                                "Ensure unified audit log is enabled. Consider E5 licensing for extended audit log retention.",
                            )
                            .build(),
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Failed to check audit log availability: {}", e);
                        findings.push(
                            Finding::new(
                                "SOC2-AUDIT-001",
                                "SOC 2",
                                "Audit Evidence",
                                "Unified Audit Log",
                                "Unable to verify audit log availability",
                            )
                            .status(FindingStatus::Warning)
                            .severity(registry.get_severity("SOC2-AUDIT-001"))
                            .current_value(format!("Unable to access audit logs: {}", e))
                            .expected_value("Audit logging should be enabled and accessible")
                            .remediation(
                                "Enable unified audit logging in Microsoft Purview compliance portal. Ensure the application has AuditLog.Read.All permission.",
                            )
                            .build(),
                        );
                    }
                }
            }
        }

        // --- SOC 2 Readiness Checklist: Manual review items ---
        let manual_items = vec![
            (
                "SOC2-MANUAL-001",
                "Security Awareness Training",
                "Verify that security awareness training is conducted annually for all employees",
            ),
            (
                "SOC2-MANUAL-002",
                "Background Checks",
                "Verify that background checks are performed for employees with access to sensitive systems",
            ),
            (
                "SOC2-MANUAL-003",
                "Business Continuity Plan",
                "Verify that a business continuity and disaster recovery plan exists and is tested annually",
            ),
            (
                "SOC2-MANUAL-004",
                "Risk Assessment",
                "Verify that a formal risk assessment is performed annually and risks are documented",
            ),
            (
                "SOC2-MANUAL-005",
                "Acceptable Use Policy",
                "Verify that an acceptable use policy exists and is acknowledged by all employees",
            ),
        ];

        for (check_id, setting, description) in manual_items {
            findings.push(
                Finding::new(
                    check_id,
                    "SOC 2",
                    "Readiness Checklist",
                    setting,
                    description,
                )
                .status(FindingStatus::Review)
                .severity(Severity::Info)
                .current_value("Manual review required")
                .expected_value("Documented and evidenced")
                .remediation(
                    "Collect evidence for this control during SOC 2 audit preparation. Maintain documentation and review annually.",
                )
                .build(),
            );
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
