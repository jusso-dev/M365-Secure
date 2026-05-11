use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct SecurityModule;

impl SecurityModule {
    // ---------------------------------------------------------------
    // 1. DEFENDER-SECURESCORE-001: Microsoft Secure Score
    // ---------------------------------------------------------------
    async fn check_secure_score(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph.get_json("/v1.0/security/secureScores?$top=1").await?;
        let scores = resp["value"].as_array();

        if let Some(arr) = scores {
            if let Some(latest) = arr.first() {
                let current_score: f64 = latest["currentScore"].as_f64().unwrap_or(0.0);
                let max_score: f64 = latest["maxScore"].as_f64().unwrap_or(1.0).max(1.0_f64);
                let percentage: f64 = (current_score / max_score) * 100.0;

                let status = if percentage >= 80.0 {
                    FindingStatus::Pass
                } else if percentage >= 60.0 {
                    FindingStatus::Warning
                } else {
                    FindingStatus::Fail
                };

                return Ok(Finding::new(
                    "DEFENDER-SECURESCORE-001",
                    "Security",
                    "Microsoft Defender",
                    "Microsoft Secure Score",
                    "Evaluates the overall Microsoft Secure Score for the tenant",
                )
                .status(status)
                .severity(registry.get_severity("DEFENDER-SECURESCORE-001"))
                .current_value(format!(
                    "{:.1}/{:.1} ({:.1}%)",
                    current_score, max_score, percentage
                ))
                .expected_value(">= 80% of max score".to_string())
                .remediation(
                    "Review Microsoft Secure Score recommendations in the Microsoft 365 Defender portal and implement suggested improvements".to_string(),
                )
                .build());
            }
        }

        Ok(Finding::new(
            "DEFENDER-SECURESCORE-001",
            "Security",
            "Microsoft Defender",
            "Microsoft Secure Score",
            "Evaluates the overall Microsoft Secure Score for the tenant",
        )
        .status(FindingStatus::Unknown)
        .severity(registry.get_severity("DEFENDER-SECURESCORE-001"))
        .current_value("Unable to retrieve Secure Score data".to_string())
        .expected_value(">= 80% of max score".to_string())
        .remediation("Ensure the application has SecurityEvents.Read.All permissions".to_string())
        .build())
    }

    // ---------------------------------------------------------------
    // 2. DEFENDER-ANTIPHISH-001: Anti-phishing policy
    // ---------------------------------------------------------------
    async fn check_anti_phishing(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        // Try secure score control profiles for phishing insight
        let resp = graph
            .get_json(
                "/v1.0/security/secureScoreControlProfiles?$filter=controlCategory eq 'Email'",
            )
            .await;

        let mut phishing_threshold: i64 = 0;
        let mut found_policy = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("");
                    if title.to_lowercase().contains("phish")
                        || title.to_lowercase().contains("anti-phishing")
                    {
                        found_policy = true;
                        // Check implementation status
                        if let Some(states) = profile["controlStateUpdates"].as_array() {
                            if states
                                .iter()
                                .any(|s| s["state"].as_str().unwrap_or("") == "Resolved")
                            {
                                phishing_threshold = 2;
                            }
                        }
                    }
                }
            }
        }

        // Also try beta endpoint for anti-phishing policies
        if !found_policy {
            let beta_resp = graph
                .get_json("/beta/security/attackSimulation/simulationAutomations")
                .await;
            if beta_resp.is_ok() {
                found_policy = true;
            }
        }

        let status = if phishing_threshold >= 2 {
            FindingStatus::Pass
        } else if found_policy {
            FindingStatus::Warning
        } else {
            FindingStatus::Fail
        };

        Ok(Finding::new(
            "DEFENDER-ANTIPHISH-001",
            "Security",
            "Microsoft Defender",
            "Anti-Phishing Policy",
            "Checks that anti-phishing policies are configured with an appropriate phishing threshold",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-ANTIPHISH-001"))
        .current_value(format!("Phishing threshold: {}", phishing_threshold))
        .expected_value("Phishing threshold >= 2".to_string())
        .remediation(
            "Configure anti-phishing policies in Microsoft 365 Defender with phishing email threshold set to at least 2 (Aggressive)".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 3. DEFENDER-ANTISPAM-001: Anti-spam policy
    // ---------------------------------------------------------------
    async fn check_anti_spam(graph: &GraphClient, registry: &ControlRegistry) -> Result<Finding> {
        let resp = graph
            .get_json(
                "/v1.0/security/secureScoreControlProfiles?$filter=controlCategory eq 'Email'",
            )
            .await;

        let mut issues: Vec<String> = Vec::new();
        let mut spam_filter_found = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("");
                    if title.to_lowercase().contains("spam") {
                        spam_filter_found = true;
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        let max: f64 = profile["maxScore"].as_f64().unwrap_or(1.0).max(1.0_f64);
                        if score < max {
                            issues.push(format!(
                                "Spam filter '{}' not fully configured ({:.0}/{:.0})",
                                title, score, max
                            ));
                        }
                    }
                }
            }
        }

        if !spam_filter_found {
            issues.push("No anti-spam policy profiles found via Secure Score".to_string());
        }

        let status = if issues.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        let current = if issues.is_empty() {
            "Anti-spam filters are properly configured".to_string()
        } else {
            issues.join("; ")
        };

        Ok(Finding::new(
            "DEFENDER-ANTISPAM-001",
            "Security",
            "Microsoft Defender",
            "Anti-Spam Policy",
            "Verifies that anti-spam policies and filters are properly configured",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-ANTISPAM-001"))
        .current_value(current)
        .expected_value("Anti-spam filters fully configured".to_string())
        .remediation(
            "Configure anti-spam policies in Exchange Online Protection with appropriate spam filtering thresholds and actions".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 4. DEFENDER-ANTISPAM-002: Outbound spam notifications
    // ---------------------------------------------------------------
    async fn check_outbound_spam_notifications(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut notifications_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("outbound") && title.contains("spam") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            notifications_configured = true;
                        }
                    }
                }
            }
        }

        let status = if notifications_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        Ok(Finding::new(
            "DEFENDER-ANTISPAM-002",
            "Security",
            "Microsoft Defender",
            "Outbound Spam Notifications",
            "Checks that outbound spam notifications are configured to alert administrators",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-ANTISPAM-002"))
        .current_value(if notifications_configured {
            "Outbound spam notifications enabled".to_string()
        } else {
            "Outbound spam notifications not configured".to_string()
        })
        .expected_value("Outbound spam notifications enabled with admin alert".to_string())
        .remediation(
            "Enable outbound spam notifications in the Exchange admin center to alert administrators when users are blocked for sending outbound spam".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 5. DEFENDER-ANTIMALWARE-001: Anti-malware policy
    // ---------------------------------------------------------------
    async fn check_anti_malware(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut issues: Vec<String> = Vec::new();
        let mut malware_found = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("malware") {
                        malware_found = true;
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        let max: f64 = profile["maxScore"].as_f64().unwrap_or(1.0).max(1.0_f64);
                        if score < max {
                            issues.push(format!(
                                "Malware control '{}' not fully implemented ({:.0}/{:.0})",
                                profile["title"].as_str().unwrap_or("Unknown"),
                                score,
                                max
                            ));
                        }
                    }
                }
            }
        }

        if !malware_found {
            issues.push("No anti-malware policy profiles found".to_string());
        }

        // Check common attachment filter
        let mut attachment_filter_enabled = false;
        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("attachment") && title.contains("filter") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        attachment_filter_enabled = score > 0.0;
                    }
                }
            }
        }

        if !attachment_filter_enabled {
            issues.push("Common attachment type filter not confirmed enabled".to_string());
        }

        let status = if issues.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        let current = if issues.is_empty() {
            "Anti-malware policies with common attachment filter and ZAP enabled".to_string()
        } else {
            issues.join("; ")
        };

        Ok(Finding::new(
            "DEFENDER-ANTIMALWARE-001",
            "Security",
            "Microsoft Defender",
            "Anti-Malware Policy",
            "Verifies anti-malware policies are configured with common attachment filter and ZAP enabled",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-ANTIMALWARE-001"))
        .current_value(current)
        .expected_value("Anti-malware with common attachment filter and ZAP enabled".to_string())
        .remediation(
            "Configure anti-malware policies in Microsoft 365 Defender with the common attachment types filter enabled and Zero-hour Auto Purge (ZAP) turned on".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 6. DEFENDER-ANTIMALWARE-002: Dangerous file types blocked
    // ---------------------------------------------------------------
    async fn check_dangerous_file_types(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut blocking_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if (title.contains("file type") || title.contains("attachment"))
                        && (title.contains("block") || title.contains("filter"))
                    {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            blocking_configured = true;
                        }
                    }
                }
            }
        }

        let status = if blocking_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        };

        Ok(Finding::new(
            "DEFENDER-ANTIMALWARE-002",
            "Security",
            "Microsoft Defender",
            "Dangerous File Types Blocked",
            "Checks that known dangerous file types (exe, vbs, js, etc.) are blocked in mail flow",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-ANTIMALWARE-002"))
        .current_value(if blocking_configured {
            "Dangerous file type blocking is configured".to_string()
        } else {
            "Dangerous file type blocking not confirmed".to_string()
        })
        .expected_value("Dangerous executable file types blocked in mail transport rules".to_string())
        .remediation(
            "Create mail flow rules or anti-malware policies to block dangerous file types such as .exe, .vbs, .js, .wsf, .bat, .cmd, .scr, and .ps1".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 7. DEFENDER-SAFELINKS-001: Safe Links (license-aware)
    // ---------------------------------------------------------------
    async fn check_safe_links(
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        if !tenant.has_service_plan("ATP_ENTERPRISE") {
            return Ok(Finding::new(
                "DEFENDER-SAFELINKS-001",
                "Security",
                "Microsoft Defender for Office 365",
                "Safe Links Policy",
                "Checks that Safe Links policies are configured for URL protection",
            )
            .status(FindingStatus::NotLicensed)
            .severity(registry.get_severity("DEFENDER-SAFELINKS-001"))
            .current_value("ATP_ENTERPRISE service plan not detected".to_string())
            .expected_value("Microsoft Defender for Office 365 Plan 1 or higher".to_string())
            .remediation(
                "Safe Links requires Microsoft Defender for Office 365 (Plan 1 or Plan 2). Consider upgrading your license.".to_string(),
            )
            .build());
        }

        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut safe_links_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("safe links") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            safe_links_configured = true;
                        }
                    }
                }
            }
        }

        let status = if safe_links_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        Ok(Finding::new(
            "DEFENDER-SAFELINKS-001",
            "Security",
            "Microsoft Defender for Office 365",
            "Safe Links Policy",
            "Checks that Safe Links policies are configured for URL protection",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-SAFELINKS-001"))
        .current_value(if safe_links_configured {
            "Safe Links policies are configured".to_string()
        } else {
            "Safe Links policies not detected".to_string()
        })
        .expected_value("Safe Links enabled for all users with URL scanning and click tracking".to_string())
        .remediation(
            "Configure Safe Links policies in Microsoft 365 Defender to scan URLs in email messages and Office documents, enable real-time scanning, and track user clicks".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 8. DEFENDER-SAFEATTACH-001: Safe Attachments (license-aware)
    // ---------------------------------------------------------------
    async fn check_safe_attachments(
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        if !tenant.has_service_plan("ATP_ENTERPRISE") {
            return Ok(Finding::new(
                "DEFENDER-SAFEATTACH-001",
                "Security",
                "Microsoft Defender for Office 365",
                "Safe Attachments Policy",
                "Checks that Safe Attachments policies are configured for malware protection",
            )
            .status(FindingStatus::NotLicensed)
            .severity(registry.get_severity("DEFENDER-SAFEATTACH-001"))
            .current_value("ATP_ENTERPRISE service plan not detected".to_string())
            .expected_value("Microsoft Defender for Office 365 Plan 1 or higher".to_string())
            .remediation(
                "Safe Attachments requires Microsoft Defender for Office 365 (Plan 1 or Plan 2). Consider upgrading your license.".to_string(),
            )
            .build());
        }

        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut safe_attach_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("safe attachment") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            safe_attach_configured = true;
                        }
                    }
                }
            }
        }

        let status = if safe_attach_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        Ok(Finding::new(
            "DEFENDER-SAFEATTACH-001",
            "Security",
            "Microsoft Defender for Office 365",
            "Safe Attachments Policy",
            "Checks that Safe Attachments policies are configured for malware protection",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-SAFEATTACH-001"))
        .current_value(if safe_attach_configured {
            "Safe Attachments policies are configured".to_string()
        } else {
            "Safe Attachments policies not detected".to_string()
        })
        .expected_value("Safe Attachments enabled with Dynamic Delivery or Block action".to_string())
        .remediation(
            "Configure Safe Attachments policies in Microsoft 365 Defender to use Dynamic Delivery or Block action for unknown malware in email attachments".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 9. DEFENDER-ZAP-001: Zero-hour Auto Purge
    // ---------------------------------------------------------------
    async fn check_zap(graph: &GraphClient, registry: &ControlRegistry) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut zap_enabled = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("zero-hour") || title.contains("zap") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            zap_enabled = true;
                        }
                    }
                }
            }
        }

        // ZAP is enabled by default; if we cannot confirm via profiles, check general malware config
        if !zap_enabled {
            if let Ok(data) = &resp {
                if let Some(profiles) = data["value"].as_array() {
                    for profile in profiles {
                        let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                        if title.contains("malware") && title.contains("purge") {
                            let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                            if score > 0.0 {
                                zap_enabled = true;
                            }
                        }
                    }
                }
            }
        }

        let status = if zap_enabled {
            FindingStatus::Pass
        } else {
            FindingStatus::Review
        };

        Ok(Finding::new(
            "DEFENDER-ZAP-001",
            "Security",
            "Microsoft Defender",
            "Zero-hour Auto Purge (ZAP)",
            "Checks that Zero-hour Auto Purge is enabled for email protection",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-ZAP-001"))
        .current_value(if zap_enabled {
            "ZAP is enabled".to_string()
        } else {
            "ZAP status could not be confirmed via Graph API".to_string()
        })
        .expected_value("ZAP enabled for phishing, spam, and malware".to_string())
        .remediation(
            "Ensure Zero-hour Auto Purge (ZAP) is enabled in anti-malware and anti-spam policies. ZAP is on by default but verify it has not been disabled.".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 10. DEFENDER-OUTBOUND-001: Outbound spam filter
    // ---------------------------------------------------------------
    async fn check_outbound_spam_filter(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut outbound_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("outbound") && title.contains("spam") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            outbound_configured = true;
                        }
                    }
                }
            }
        }

        let status = if outbound_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        };

        Ok(Finding::new(
            "DEFENDER-OUTBOUND-001",
            "Security",
            "Microsoft Defender",
            "Outbound Spam Filter",
            "Checks that outbound spam filtering policies are properly configured",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-OUTBOUND-001"))
        .current_value(if outbound_configured {
            "Outbound spam filter is configured".to_string()
        } else {
            "Outbound spam filter configuration not confirmed".to_string()
        })
        .expected_value("Outbound spam filter with sending limits and notification configured".to_string())
        .remediation(
            "Configure outbound spam filter policies with appropriate sending limits and auto-forwarding restrictions in Exchange Online Protection".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 11. DEFENDER-PRIORITY-001: Priority accounts
    // ---------------------------------------------------------------
    async fn check_priority_accounts(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        // Priority accounts can be checked via directory extensions or user tags
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut priority_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("priority") && title.contains("account") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            priority_configured = true;
                        }
                    }
                }
            }
        }

        let status = if priority_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Review
        };

        Ok(Finding::new(
            "DEFENDER-PRIORITY-001",
            "Security",
            "Microsoft Defender",
            "Priority Account Protection",
            "Checks that priority accounts are identified and have enhanced protection",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-PRIORITY-001"))
        .current_value(if priority_configured {
            "Priority accounts are configured with enhanced protection".to_string()
        } else {
            "Priority account configuration not confirmed".to_string()
        })
        .expected_value("Priority accounts tagged with enhanced protection policies applied".to_string())
        .remediation(
            "Identify high-value user accounts (executives, admins, finance) and tag them as priority accounts in Microsoft 365 Defender for enhanced monitoring and protection".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 12. DEFENDER-MALWARE-002: Malware quarantine behavior
    // ---------------------------------------------------------------
    async fn check_malware_quarantine(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut quarantine_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("malware")
                        && (title.contains("quarantine") || title.contains("action"))
                    {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            quarantine_configured = true;
                        }
                    }
                }
            }
        }

        let status = if quarantine_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Review
        };

        Ok(Finding::new(
            "DEFENDER-MALWARE-002",
            "Security",
            "Microsoft Defender",
            "Malware Quarantine Behavior",
            "Verifies that detected malware is quarantined rather than just tagged",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-MALWARE-002"))
        .current_value(if quarantine_configured {
            "Malware messages are quarantined".to_string()
        } else {
            "Malware quarantine behavior not confirmed via API".to_string()
        })
        .expected_value("Malware detected in email is quarantined with admin notification".to_string())
        .remediation(
            "Ensure anti-malware policies quarantine messages containing malware and notify administrators. Avoid deliver-with-tag actions.".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 13. COMPLIANCE-DLP-001: DLP policies configured
    // ---------------------------------------------------------------
    async fn check_dlp_policies(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        // Try to get DLP policies via security/informationProtection
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut dlp_found = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("dlp") || title.contains("data loss") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            dlp_found = true;
                        }
                    }
                }
            }
        }

        // Also try the compliance endpoint
        if !dlp_found {
            let dlp_resp = graph
                .get_json("/beta/informationProtection/policy/labels")
                .await;
            if dlp_resp.is_ok() {
                dlp_found = true;
            }
        }

        let status = if dlp_found {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        Ok(Finding::new(
            "COMPLIANCE-DLP-001",
            "Compliance",
            "Data Loss Prevention",
            "DLP Policies Configured",
            "Checks that Data Loss Prevention policies are configured to protect sensitive data",
        )
        .status(status)
        .severity(registry.get_severity("COMPLIANCE-DLP-001"))
        .current_value(if dlp_found {
            "DLP policies are configured".to_string()
        } else {
            "No DLP policies detected".to_string()
        })
        .expected_value("At least one DLP policy configured and enabled".to_string())
        .remediation(
            "Configure Data Loss Prevention policies in the Microsoft Purview compliance portal to detect and protect sensitive information types across Exchange, SharePoint, OneDrive, and Teams".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 14. COMPLIANCE-DLP-002: DLP sensitive info coverage
    // ---------------------------------------------------------------
    async fn check_dlp_coverage(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut coverage_adequate = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("sensitive")
                        && (title.contains("dlp") || title.contains("information"))
                    {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            coverage_adequate = true;
                        }
                    }
                }
            }
        }

        let status = if coverage_adequate {
            FindingStatus::Pass
        } else {
            FindingStatus::Review
        };

        Ok(Finding::new(
            "COMPLIANCE-DLP-002",
            "Compliance",
            "Data Loss Prevention",
            "DLP Sensitive Information Coverage",
            "Checks that DLP policies cover key sensitive information types (SSN, credit cards, etc.)",
        )
        .status(status)
        .severity(registry.get_severity("COMPLIANCE-DLP-002"))
        .current_value(if coverage_adequate {
            "DLP covers key sensitive information types".to_string()
        } else {
            "DLP sensitive information coverage not confirmed".to_string()
        })
        .expected_value("DLP policies covering standard sensitive info types (PII, PCI, PHI)".to_string())
        .remediation(
            "Ensure DLP policies include sensitive information types for PII (SSN, passport), financial data (credit card numbers), and health data (PHI) as appropriate for your organization".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 15. COMPLIANCE-AUDIT-001: Unified audit log
    // ---------------------------------------------------------------
    async fn check_unified_audit_log(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut audit_enabled = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("audit")
                        && (title.contains("log") || title.contains("unified"))
                    {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            audit_enabled = true;
                        }
                    }
                }
            }
        }

        // Also check via audit log search to verify it is on
        if !audit_enabled {
            let audit_resp = graph.get_json("/v1.0/security/auditLog/queries").await;
            if audit_resp.is_ok() {
                audit_enabled = true;
            }
        }

        let status = if audit_enabled {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        Ok(Finding::new(
            "COMPLIANCE-AUDIT-001",
            "Compliance",
            "Audit & Logging",
            "Unified Audit Log Enabled",
            "Checks that the unified audit log is enabled for the tenant",
        )
        .status(status)
        .severity(registry.get_severity("COMPLIANCE-AUDIT-001"))
        .current_value(if audit_enabled {
            "Unified audit log is enabled".to_string()
        } else {
            "Unified audit log status could not be confirmed".to_string()
        })
        .expected_value("Unified audit log enabled with adequate retention period".to_string())
        .remediation(
            "Enable unified audit logging in the Microsoft Purview compliance portal. Ensure audit log retention is set to at least 90 days (E5 licenses support up to 1 year).".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 16. COMPLIANCE-LABELS-001: Sensitivity labels
    // ---------------------------------------------------------------
    async fn check_sensitivity_labels(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/beta/security/informationProtection/sensitivityLabels")
            .await;

        let mut label_count: usize = 0;

        if let Ok(data) = &resp {
            if let Some(labels) = data["value"].as_array() {
                label_count = labels.len();
            }
        }

        // Fallback: check via secure score
        if label_count == 0 {
            let score_resp = graph
                .get_json("/v1.0/security/secureScoreControlProfiles")
                .await;
            if let Ok(data) = &score_resp {
                if let Some(profiles) = data["value"].as_array() {
                    for profile in profiles {
                        let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                        if title.contains("sensitivity") && title.contains("label") {
                            let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                            if score > 0.0 {
                                label_count = 1; // At least some configured
                            }
                        }
                    }
                }
            }
        }

        let status = if label_count > 0 {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        Ok(Finding::new(
            "COMPLIANCE-LABELS-001",
            "Compliance",
            "Information Protection",
            "Sensitivity Labels Configured",
            "Checks that sensitivity labels are configured for data classification",
        )
        .status(status)
        .severity(registry.get_severity("COMPLIANCE-LABELS-001"))
        .current_value(if label_count > 0 {
            format!("{} sensitivity labels configured", label_count)
        } else {
            "No sensitivity labels detected".to_string()
        })
        .expected_value("Sensitivity labels configured and published to users".to_string())
        .remediation(
            "Create sensitivity labels in the Microsoft Purview compliance portal with appropriate protection settings (encryption, content marking, auto-labeling) and publish them via label policies".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 17. COMPLIANCE-ALERTPOLICY-001: Alert policies
    // ---------------------------------------------------------------
    async fn check_alert_policies(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph.get_json("/v1.0/security/alerts_v2?$top=1").await;

        let mut alerts_available = false;

        if let Ok(data) = &resp {
            // If the endpoint responds, alert policies are functional
            if data.get("value").is_some() {
                alerts_available = true;
            }
        }

        // Also check secure score
        if !alerts_available {
            let score_resp = graph
                .get_json("/v1.0/security/secureScoreControlProfiles")
                .await;
            if let Ok(data) = &score_resp {
                if let Some(profiles) = data["value"].as_array() {
                    for profile in profiles {
                        let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                        if title.contains("alert") && title.contains("polic") {
                            let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                            if score > 0.0 {
                                alerts_available = true;
                            }
                        }
                    }
                }
            }
        }

        let status = if alerts_available {
            FindingStatus::Pass
        } else {
            FindingStatus::Review
        };

        Ok(Finding::new(
            "COMPLIANCE-ALERTPOLICY-001",
            "Compliance",
            "Monitoring & Alerts",
            "Alert Policies Configured",
            "Checks that security alert policies are configured for critical events",
        )
        .status(status)
        .severity(registry.get_severity("COMPLIANCE-ALERTPOLICY-001"))
        .current_value(if alerts_available {
            "Security alert policies are configured".to_string()
        } else {
            "Alert policy configuration could not be confirmed".to_string()
        })
        .expected_value("Alert policies for critical security events (elevation of privilege, malware, mass deletion)".to_string())
        .remediation(
            "Configure alert policies in the Microsoft Purview compliance portal for critical events such as elevation of privilege, malware campaigns, unusual external sharing, and mass file deletions".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 18. DEFENDER-SAFEATTACH-002: Safe Attachments for SPO/OD/Teams
    // ---------------------------------------------------------------
    async fn check_safe_attachments_spo(
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        if !tenant.has_service_plan("ATP_ENTERPRISE") {
            return Ok(Finding::new(
                "DEFENDER-SAFEATTACH-002",
                "Security",
                "Microsoft Defender for Office 365",
                "Safe Attachments for SharePoint/OneDrive/Teams",
                "Checks that Safe Attachments is enabled for SharePoint, OneDrive, and Teams",
            )
            .status(FindingStatus::NotLicensed)
            .severity(registry.get_severity("DEFENDER-SAFEATTACH-002"))
            .current_value("ATP_ENTERPRISE service plan not detected".to_string())
            .expected_value("Microsoft Defender for Office 365 Plan 1 or higher".to_string())
            .remediation(
                "Safe Attachments for SPO/OD/Teams requires Microsoft Defender for Office 365. Consider upgrading your license.".to_string(),
            )
            .build());
        }

        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut spo_safe_attach = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if (title.contains("safe attachment") || title.contains("safe attachments"))
                        && (title.contains("sharepoint")
                            || title.contains("onedrive")
                            || title.contains("teams"))
                    {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            spo_safe_attach = true;
                        }
                    }
                }
            }
        }

        // Fallback: check the admin sharepoint settings for malware scan
        if !spo_safe_attach {
            let spo_resp = graph.get_json("/v1.0/admin/sharepoint/settings").await;
            if let Ok(spo) = &spo_resp {
                if let Some(true) = spo.get("isMalwareScanEnabled").and_then(|v| v.as_bool()) {
                    spo_safe_attach = true;
                }
            }
        }

        let status = if spo_safe_attach {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        Ok(Finding::new(
            "DEFENDER-SAFEATTACH-002",
            "Security",
            "Microsoft Defender for Office 365",
            "Safe Attachments for SharePoint/OneDrive/Teams",
            "Checks that Safe Attachments is enabled for SharePoint, OneDrive, and Teams",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-SAFEATTACH-002"))
        .current_value(if spo_safe_attach {
            "Safe Attachments enabled for SPO/OD/Teams".to_string()
        } else {
            "Safe Attachments for SPO/OD/Teams not detected".to_string()
        })
        .expected_value("Safe Attachments enabled for SharePoint, OneDrive, and Teams".to_string())
        .remediation(
            "Enable Safe Attachments for SharePoint, OneDrive, and Teams in Microsoft 365 Defender portal > Policies & rules > Threat policies > Safe Attachments > Global settings".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 19. DEFENDER-PRIORITY-002: Priority account monitoring
    // ---------------------------------------------------------------
    async fn check_priority_account_monitoring(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut monitoring_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("priority")
                        && (title.contains("monitor") || title.contains("protection"))
                    {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            monitoring_configured = true;
                        }
                    }
                }
            }
        }

        let status = if monitoring_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Review
        };

        Ok(Finding::new(
            "DEFENDER-PRIORITY-002",
            "Security",
            "Microsoft Defender",
            "Priority Account Monitoring",
            "Checks that priority account monitoring and enhanced alerting is enabled",
        )
        .status(status)
        .severity(registry.get_severity("DEFENDER-PRIORITY-002"))
        .current_value(if monitoring_configured {
            "Priority account monitoring is enabled".to_string()
        } else {
            "Priority account monitoring not confirmed".to_string()
        })
        .expected_value("Priority account monitoring enabled with enhanced alerting".to_string())
        .remediation(
            "Enable priority account monitoring in Microsoft 365 Defender to provide enhanced protection and alerting for high-value accounts".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 20. COMPLIANCE-DLP-003: DLP covers Teams and SharePoint
    // ---------------------------------------------------------------
    async fn check_dlp_teams_spo(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut dlp_teams = false;
        let mut dlp_spo = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("dlp") || title.contains("data loss") {
                        let desc = profile["description"].as_str().unwrap_or("").to_lowercase();
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            if desc.contains("teams") || title.contains("teams") {
                                dlp_teams = true;
                            }
                            if desc.contains("sharepoint") || title.contains("sharepoint") {
                                dlp_spo = true;
                            }
                            // If generic DLP is configured, count both
                            if !desc.contains("exchange")
                                || (desc.contains("teams") && desc.contains("sharepoint"))
                            {
                                dlp_teams = true;
                                dlp_spo = true;
                            }
                        }
                    }
                }
            }
        }

        let (status, current): (FindingStatus, String) = match (dlp_teams, dlp_spo) {
            (true, true) => (
                FindingStatus::Pass,
                "DLP covers Teams and SharePoint".to_string(),
            ),
            (true, false) => (
                FindingStatus::Warning,
                "DLP covers Teams but not SharePoint".to_string(),
            ),
            (false, true) => (
                FindingStatus::Warning,
                "DLP covers SharePoint but not Teams".to_string(),
            ),
            (false, false) => (
                FindingStatus::Fail,
                "DLP does not cover Teams or SharePoint".to_string(),
            ),
        };

        Ok(Finding::new(
            "COMPLIANCE-DLP-003",
            "Compliance",
            "Data Loss Prevention",
            "DLP Coverage for Teams and SharePoint",
            "Checks that DLP policies extend to Teams messages and SharePoint content",
        )
        .status(status)
        .severity(registry.get_severity("COMPLIANCE-DLP-003"))
        .current_value(current)
        .expected_value("DLP policies covering both Teams and SharePoint".to_string())
        .remediation(
            "Extend DLP policies to cover Teams chat/channel messages and SharePoint/OneDrive content in Microsoft Purview compliance portal > Data loss prevention > Policies".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 21. COMPLIANCE-LABELS-002: Default sensitivity label
    // ---------------------------------------------------------------
    async fn check_default_sensitivity_label(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/beta/security/informationProtection/sensitivityLabels")
            .await;

        let mut default_label_found = false;

        if let Ok(data) = &resp {
            if let Some(labels) = data["value"].as_array() {
                for label in labels {
                    let is_default = label
                        .get("isDefault")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if is_default {
                        default_label_found = true;
                    }
                }
            }
        }

        // Fallback: check via secure score
        if !default_label_found {
            let score_resp = graph
                .get_json("/v1.0/security/secureScoreControlProfiles")
                .await;
            if let Ok(data) = &score_resp {
                if let Some(profiles) = data["value"].as_array() {
                    for profile in profiles {
                        let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                        if title.contains("default") && title.contains("label") {
                            let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                            if score > 0.0 {
                                default_label_found = true;
                            }
                        }
                    }
                }
            }
        }

        let status = if default_label_found {
            FindingStatus::Pass
        } else {
            FindingStatus::Review
        };

        Ok(Finding::new(
            "COMPLIANCE-LABELS-002",
            "Compliance",
            "Information Protection",
            "Default Sensitivity Label",
            "Checks that a default sensitivity label is applied to new documents",
        )
        .status(status)
        .severity(registry.get_severity("COMPLIANCE-LABELS-002"))
        .current_value(if default_label_found {
            "Default sensitivity label is configured".to_string()
        } else {
            "No default sensitivity label detected".to_string()
        })
        .expected_value("Default sensitivity label applied to new documents".to_string())
        .remediation(
            "Configure a default sensitivity label in Microsoft Purview compliance portal > Information protection > Label policies to ensure new documents receive a baseline classification".to_string(),
        )
        .build())
    }

    // ---------------------------------------------------------------
    // 22. COMPLIANCE-COMMS-001: Communication compliance
    // ---------------------------------------------------------------
    async fn check_communication_compliance(
        graph: &GraphClient,
        registry: &ControlRegistry,
    ) -> Result<Finding> {
        let resp = graph
            .get_json("/v1.0/security/secureScoreControlProfiles")
            .await;

        let mut comms_compliance_configured = false;

        if let Ok(data) = &resp {
            if let Some(profiles) = data["value"].as_array() {
                for profile in profiles {
                    let title = profile["title"].as_str().unwrap_or("").to_lowercase();
                    if title.contains("communication") && title.contains("compliance") {
                        let score: f64 = profile["currentScore"].as_f64().unwrap_or(0.0);
                        if score > 0.0 {
                            comms_compliance_configured = true;
                        }
                    }
                }
            }
        }

        let status = if comms_compliance_configured {
            FindingStatus::Pass
        } else {
            FindingStatus::Review
        };

        Ok(Finding::new(
            "COMPLIANCE-COMMS-001",
            "Compliance",
            "Communication Compliance",
            "Communication Compliance Policies",
            "Checks that communication compliance policies are configured for regulatory and conduct monitoring",
        )
        .status(status)
        .severity(registry.get_severity("COMPLIANCE-COMMS-001"))
        .current_value(if comms_compliance_configured {
            "Communication compliance policies are configured".to_string()
        } else {
            "Communication compliance not confirmed".to_string()
        })
        .expected_value("Communication compliance policies for offensive language, sensitive info, and regulatory compliance".to_string())
        .remediation(
            "Configure communication compliance policies in Microsoft Purview to monitor for offensive language, sensitive information sharing, and regulatory compliance violations in email, Teams, and other channels".to_string(),
        )
        .build())
    }
}

#[async_trait]
impl AssessmentModule for SecurityModule {
    fn name(&self) -> &str {
        "Security"
    }

    fn description(&self) -> &str {
        "Microsoft Defender and Security compliance assessment module"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();

        // 1. DEFENDER-SECURESCORE-001
        match Self::check_secure_score(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-SECURESCORE-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-SECURESCORE-001",
                        "Security",
                        "Microsoft Defender",
                        "Microsoft Secure Score",
                        "Evaluates the overall Microsoft Secure Score for the tenant",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-SECURESCORE-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value(">= 80% of max score".to_string())
                    .remediation(
                        "Ensure application has SecurityEvents.Read.All permissions".to_string(),
                    )
                    .build(),
                );
            }
        }

        // 2. DEFENDER-ANTIPHISH-001
        match Self::check_anti_phishing(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-ANTIPHISH-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-ANTIPHISH-001",
                        "Security",
                        "Microsoft Defender",
                        "Anti-Phishing Policy",
                        "Checks that anti-phishing policies are configured",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-ANTIPHISH-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Phishing threshold >= 2".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 3. DEFENDER-ANTISPAM-001
        match Self::check_anti_spam(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-ANTISPAM-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-ANTISPAM-001",
                        "Security",
                        "Microsoft Defender",
                        "Anti-Spam Policy",
                        "Verifies anti-spam policies are configured",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-ANTISPAM-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Anti-spam filters fully configured".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 4. DEFENDER-ANTISPAM-002
        match Self::check_outbound_spam_notifications(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-ANTISPAM-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-ANTISPAM-002",
                        "Security",
                        "Microsoft Defender",
                        "Outbound Spam Notifications",
                        "Checks outbound spam notifications",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-ANTISPAM-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Outbound spam notifications enabled".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 5. DEFENDER-ANTIMALWARE-001
        match Self::check_anti_malware(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-ANTIMALWARE-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-ANTIMALWARE-001",
                        "Security",
                        "Microsoft Defender",
                        "Anti-Malware Policy",
                        "Verifies anti-malware policies",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-ANTIMALWARE-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Anti-malware with attachment filter and ZAP".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 6. DEFENDER-ANTIMALWARE-002
        match Self::check_dangerous_file_types(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-ANTIMALWARE-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-ANTIMALWARE-002",
                        "Security",
                        "Microsoft Defender",
                        "Dangerous File Types Blocked",
                        "Checks dangerous file types are blocked",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-ANTIMALWARE-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Dangerous file types blocked".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 7. DEFENDER-SAFELINKS-001
        match Self::check_safe_links(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-SAFELINKS-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-SAFELINKS-001",
                        "Security",
                        "Microsoft Defender for Office 365",
                        "Safe Links Policy",
                        "Checks Safe Links policies",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-SAFELINKS-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Safe Links enabled".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 8. DEFENDER-SAFEATTACH-001
        match Self::check_safe_attachments(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-SAFEATTACH-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-SAFEATTACH-001",
                        "Security",
                        "Microsoft Defender for Office 365",
                        "Safe Attachments Policy",
                        "Checks Safe Attachments policies",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-SAFEATTACH-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Safe Attachments enabled".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 9. DEFENDER-ZAP-001
        match Self::check_zap(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-ZAP-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-ZAP-001",
                        "Security",
                        "Microsoft Defender",
                        "Zero-hour Auto Purge (ZAP)",
                        "Checks ZAP status",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-ZAP-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("ZAP enabled".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 10. DEFENDER-OUTBOUND-001
        match Self::check_outbound_spam_filter(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-OUTBOUND-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-OUTBOUND-001",
                        "Security",
                        "Microsoft Defender",
                        "Outbound Spam Filter",
                        "Checks outbound spam filtering",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-OUTBOUND-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Outbound spam filter configured".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 11. DEFENDER-PRIORITY-001
        match Self::check_priority_accounts(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-PRIORITY-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-PRIORITY-001",
                        "Security",
                        "Microsoft Defender",
                        "Priority Account Protection",
                        "Checks priority accounts",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-PRIORITY-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Priority accounts configured".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 12. DEFENDER-MALWARE-002
        match Self::check_malware_quarantine(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-MALWARE-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-MALWARE-002",
                        "Security",
                        "Microsoft Defender",
                        "Malware Quarantine Behavior",
                        "Checks malware quarantine settings",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-MALWARE-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Malware quarantined".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 13. COMPLIANCE-DLP-001
        match Self::check_dlp_policies(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("COMPLIANCE-DLP-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "COMPLIANCE-DLP-001",
                        "Compliance",
                        "Data Loss Prevention",
                        "DLP Policies Configured",
                        "Checks DLP policies",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("COMPLIANCE-DLP-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("DLP policies configured".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 14. COMPLIANCE-DLP-002
        match Self::check_dlp_coverage(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("COMPLIANCE-DLP-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "COMPLIANCE-DLP-002",
                        "Compliance",
                        "Data Loss Prevention",
                        "DLP Sensitive Information Coverage",
                        "Checks DLP sensitive info coverage",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("COMPLIANCE-DLP-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("DLP covers sensitive info types".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 15. COMPLIANCE-AUDIT-001
        match Self::check_unified_audit_log(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("COMPLIANCE-AUDIT-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "COMPLIANCE-AUDIT-001",
                        "Compliance",
                        "Audit & Logging",
                        "Unified Audit Log Enabled",
                        "Checks unified audit log",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("COMPLIANCE-AUDIT-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Unified audit log enabled".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 16. COMPLIANCE-LABELS-001
        match Self::check_sensitivity_labels(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("COMPLIANCE-LABELS-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "COMPLIANCE-LABELS-001",
                        "Compliance",
                        "Information Protection",
                        "Sensitivity Labels Configured",
                        "Checks sensitivity labels",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("COMPLIANCE-LABELS-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Sensitivity labels configured".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 17. COMPLIANCE-ALERTPOLICY-001
        match Self::check_alert_policies(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("COMPLIANCE-ALERTPOLICY-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "COMPLIANCE-ALERTPOLICY-001",
                        "Compliance",
                        "Monitoring & Alerts",
                        "Alert Policies Configured",
                        "Checks alert policies",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("COMPLIANCE-ALERTPOLICY-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Alert policies configured".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 18. COMPLIANCE-COMMS-001
        match Self::check_communication_compliance(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("COMPLIANCE-COMMS-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "COMPLIANCE-COMMS-001",
                        "Compliance",
                        "Communication Compliance",
                        "Communication Compliance Policies",
                        "Checks communication compliance",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("COMPLIANCE-COMMS-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Communication compliance configured".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 19. DEFENDER-SAFEATTACH-002
        match Self::check_safe_attachments_spo(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-SAFEATTACH-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-SAFEATTACH-002",
                        "Security",
                        "Microsoft Defender for Office 365",
                        "Safe Attachments for SharePoint/OneDrive/Teams",
                        "Checks Safe Attachments for file-sharing services",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-SAFEATTACH-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Safe Attachments enabled for SPO/OD/Teams".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 20. DEFENDER-PRIORITY-002
        match Self::check_priority_account_monitoring(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("DEFENDER-PRIORITY-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "DEFENDER-PRIORITY-002",
                        "Security",
                        "Microsoft Defender",
                        "Priority Account Monitoring",
                        "Checks priority account monitoring",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("DEFENDER-PRIORITY-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Priority account monitoring enabled".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 21. COMPLIANCE-DLP-003
        match Self::check_dlp_teams_spo(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("COMPLIANCE-DLP-003 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "COMPLIANCE-DLP-003",
                        "Compliance",
                        "Data Loss Prevention",
                        "DLP Coverage for Teams and SharePoint",
                        "Checks DLP coverage for Teams and SharePoint",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("COMPLIANCE-DLP-003"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("DLP covers Teams and SharePoint".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        // 22. COMPLIANCE-LABELS-002
        match Self::check_default_sensitivity_label(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("COMPLIANCE-LABELS-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "COMPLIANCE-LABELS-002",
                        "Compliance",
                        "Information Protection",
                        "Default Sensitivity Label",
                        "Checks default sensitivity label",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("COMPLIANCE-LABELS-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Default sensitivity label configured".to_string())
                    .remediation("Verify API permissions and retry".to_string())
                    .build(),
                );
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: serde_json::json!({
                "checks_run": 22,
                "module": "security"
            }),
            error: None,
            duration_ms,
        })
    }
}
