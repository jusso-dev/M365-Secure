use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

pub struct ExchangeModule;

/// Helper to build the Exchange admin REST API base URL for a tenant.
fn exo_admin_url(tenant_id: &str, path: &str) -> String {
    format!(
        "https://outlook.office365.com/adminapi/beta/{}/{}",
        tenant_id, path
    )
}

/// Fetch Microsoft Secure Score control profiles and extract scores by control name.
/// Returns a map of control name (lowercase) -> (score, max_score, description).
async fn fetch_secure_score_controls(
    graph: &GraphClient,
) -> Result<std::collections::HashMap<String, SecureScoreControl>> {
    let mut controls = std::collections::HashMap::new();

    // Get secure score control profiles
    match graph
        .get_json("/v1.0/security/secureScoreControlProfiles")
        .await
    {
        Ok(data) => {
            if let Some(values) = data["value"].as_array() {
                for ctrl in values {
                    let id = ctrl["id"].as_str().unwrap_or("").to_lowercase();
                    let max_score = ctrl["maxScore"].as_f64().unwrap_or(0.0);
                    let deprecated = ctrl["deprecated"].as_bool().unwrap_or(false);

                    if !deprecated && !id.is_empty() {
                        controls.insert(
                            id.clone(),
                            SecureScoreControl {
                                max_score,
                                current_score: None,
                            },
                        );
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to fetch secure score control profiles: {}", e);
        }
    }

    // Get latest secure score with actual scores
    match graph.get_json("/v1.0/security/secureScores?$top=1").await {
        Ok(data) => {
            if let Some(scores) = data["value"].as_array().and_then(|a| a.first()) {
                if let Some(ctrl_scores) = scores["controlScores"].as_array() {
                    for cs in ctrl_scores {
                        let name = cs["controlName"].as_str().unwrap_or("").to_lowercase();
                        let score = cs["score"].as_f64().unwrap_or(0.0);

                        if let Some(ctrl) = controls.get_mut(&name) {
                            ctrl.current_score = Some(score);
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to fetch secure scores: {}", e);
        }
    }

    Ok(controls)
}

#[derive(Debug, Clone)]
struct SecureScoreControl {
    max_score: f64,
    current_score: Option<f64>,
}

/// Try EXO API first, fall back to Secure Score control data.
/// Returns (status, current_value, source) based on best available data.
fn evaluate_from_secure_score(
    controls: &std::collections::HashMap<String, SecureScoreControl>,
    control_names: &[&str],
    check_description: &str,
) -> (FindingStatus, String) {
    for name in control_names {
        let name_lower = name.to_lowercase();
        if let Some(ctrl) = controls.get(&name_lower) {
            if let Some(score) = ctrl.current_score {
                if score >= ctrl.max_score && ctrl.max_score > 0.0 {
                    return (
                        FindingStatus::Pass,
                        format!(
                            "{} (via Secure Score: {:.0}/{:.0})",
                            check_description, score, ctrl.max_score
                        ),
                    );
                } else if score > 0.0 {
                    return (
                        FindingStatus::Warning,
                        format!(
                            "Partially configured (Secure Score: {:.0}/{:.0})",
                            score, ctrl.max_score
                        ),
                    );
                } else {
                    return (
                        FindingStatus::Fail,
                        format!("Not configured (Secure Score: 0/{:.0})", ctrl.max_score),
                    );
                }
            }
        }
    }
    // No Secure Score data found
    (
        FindingStatus::Review,
        "Unable to verify automatically. Requires Exchange Online PowerShell.".to_string(),
    )
}

#[async_trait]
impl AssessmentModule for ExchangeModule {
    fn name(&self) -> &str {
        "Exchange"
    }

    fn description(&self) -> &str {
        "Exchange Online security assessment module"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();

        // Pre-fetch Secure Score control data for fallback evaluation
        let secure_score_controls = fetch_secure_score_controls(graph).await.unwrap_or_default();
        tracing::info!(
            "Loaded {} Secure Score controls for Exchange fallback evaluation",
            secure_score_controls.len()
        );

        // ── EXO-AUTH-001: Modern Authentication ──────────────────────────
        match check_modern_auth(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-AUTH-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-AUTH-001",
                        "Exchange Online",
                        "Authentication",
                        "Modern Authentication",
                        "Verify modern authentication is enabled for Exchange Online",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-AUTH-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Modern authentication enabled")
                    .remediation("Manually verify modern authentication is enabled in the Exchange admin center.")
                    .build(),
                );
            }
        }

        // ── EXO-AUTH-002: Basic Authentication Disabled ──────────────────
        match check_basic_auth_disabled(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-AUTH-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-AUTH-002",
                        "Exchange Online",
                        "Authentication",
                        "Basic Authentication Disabled",
                        "Verify basic authentication is disabled via security defaults or conditional access",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-AUTH-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Basic authentication blocked")
                    .remediation("Manually verify basic authentication is blocked via security defaults or conditional access policies.")
                    .build(),
                );
            }
        }

        // ── EXO-AUDIT-001: Mailbox Auditing ─────────────────────────────
        match check_mailbox_auditing(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-AUDIT-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-AUDIT-001",
                        "Exchange Online",
                        "Auditing",
                        "Mailbox Auditing",
                        "Verify mailbox auditing is enabled organization-wide",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-AUDIT-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Mailbox auditing enabled (default since 2019)")
                    .remediation("Verify mailbox auditing via Exchange Online PowerShell: Get-OrganizationConfig | FL AuditDisabled")
                    .build(),
                );
            }
        }

        // ── EXO-AUDIT-002: Admin Audit Log ──────────────────────────────
        match check_admin_audit_log(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-AUDIT-002 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-AUDIT-002",
                        "Exchange Online",
                        "Auditing",
                        "Admin Audit Log",
                        "Verify admin audit logging is enabled",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-AUDIT-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Admin audit log enabled")
                    .remediation("Verify via Exchange Online PowerShell: Get-AdminAuditLogConfig | FL AdminAuditLogEnabled")
                    .build(),
                );
            }
        }

        // ── EXO-EXTTAG-001: External Sender Tagging ─────────────────────
        match check_external_sender_tagging(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-EXTTAG-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-EXTTAG-001",
                        "Exchange Online",
                        "Mail Flow",
                        "External Sender Tagging",
                        "Verify external sender tagging is enabled to flag emails from outside the organization",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-EXTTAG-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("External sender tagging enabled")
                    .remediation("Enable via Exchange Online PowerShell: Set-ExternalInOutlook -Enabled $true")
                    .build(),
                );
            }
        }

        // ── EXO-FORWARD-001: Auto-Forwarding Disabled ───────────────────
        match check_auto_forwarding(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-FORWARD-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-FORWARD-001",
                        "Exchange Online",
                        "Mail Flow",
                        "Auto-Forwarding to External Recipients",
                        "Verify automatic forwarding to external recipients is disabled",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-FORWARD-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Auto-forwarding to external recipients disabled")
                    .remediation(
                        "Disable via remote domains or transport rules in Exchange admin center.",
                    )
                    .build(),
                );
            }
        }

        // ── EXO-LOCKBOX-001: Customer Lockbox ───────────────────────────
        match check_customer_lockbox(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-LOCKBOX-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-LOCKBOX-001",
                        "Exchange Online",
                        "Data Protection",
                        "Customer Lockbox",
                        "Verify Customer Lockbox is enabled for Microsoft support access requests",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-LOCKBOX-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Customer Lockbox enabled (E5 required)")
                    .remediation("Enable Customer Lockbox in the Microsoft 365 admin center under Settings > Org settings > Security & privacy.")
                    .build(),
                );
            }
        }

        // ── EXO-MAILTIPS-001: MailTips for External Recipients ──────────
        match check_mailtips(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-MAILTIPS-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-MAILTIPS-001",
                        "Exchange Online",
                        "Mail Flow",
                        "MailTips External Recipients",
                        "Verify MailTips are enabled to warn users when emailing external recipients",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-MAILTIPS-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("MailTips for external recipients enabled")
                    .remediation("Enable via Exchange Online PowerShell: Set-OrganizationConfig -MailTipsExternalRecipientsTipsEnabled $true")
                    .build(),
                );
            }
        }

        // ── EXO-OWA-001: OWA Policy Restrictions ───────────────────────
        match check_owa_policy(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-OWA-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-OWA-001",
                        "Exchange Online",
                        "Client Access",
                        "OWA Mailbox Policy",
                        "Verify OWA mailbox policy restricts risky features",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-OWA-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("OWA policy restricts external storage and additional features")
                    .remediation("Review OWA mailbox policies via Exchange Online PowerShell: Get-OwaMailboxPolicy | FL")
                    .build(),
                );
            }
        }

        // ── EXO-SHAREDMBX-001: Shared Mailbox Sign-In Disabled ─────────
        match check_shared_mailbox_signin(graph, registry).await {
            Ok(mut f_vec) => findings.append(&mut f_vec),
            Err(e) => {
                tracing::warn!("EXO-SHAREDMBX-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-SHAREDMBX-001",
                        "Exchange Online",
                        "Mailbox Security",
                        "Shared Mailbox Direct Sign-In",
                        "Verify shared mailboxes have direct sign-in disabled",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-SHAREDMBX-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Shared mailbox sign-in disabled")
                    .remediation("Disable sign-in for shared mailboxes in the Microsoft 365 admin center or via PowerShell.")
                    .build(),
                );
            }
        }

        // ── EXO-SHARING-001: Calendar Sharing Restrictions ──────────────
        match check_calendar_sharing(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-SHARING-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-SHARING-001",
                        "Exchange Online",
                        "Sharing",
                        "Calendar Sharing Policy",
                        "Verify calendar sharing with external recipients is restricted",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-SHARING-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Calendar sharing restricted to free/busy only for external recipients")
                    .remediation("Review sharing policies via Exchange Online PowerShell: Get-SharingPolicy | FL")
                    .build(),
                );
            }
        }

        // ── EXO-TRANSPORT-001: Transport Rules Review ───────────────────
        match check_transport_rules(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-TRANSPORT-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-TRANSPORT-001",
                        "Exchange Online",
                        "Mail Flow",
                        "Transport Rules",
                        "Review transport rules for security implications",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-TRANSPORT-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Transport rules reviewed and no overly permissive rules")
                    .remediation(
                        "Review transport rules in Exchange admin center > Mail flow > Rules.",
                    )
                    .build(),
                );
            }
        }

        // ── EXO-CONNFILTER-001: Connection Filter IP Allow List ─────────
        match check_connection_filter(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-CONNFILTER-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-CONNFILTER-001",
                        "Exchange Online",
                        "Mail Flow",
                        "Connection Filter IP Allow List",
                        "Verify the connection filter IP allow list is not overly broad",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-CONNFILTER-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Connection filter IP allow list is empty or minimal")
                    .remediation("Review the connection filter policy in Exchange admin center > Mail flow > Connection filtering.")
                    .build(),
                );
            }
        }

        // ── EXO-ADDINS-001: User Add-In Restrictions ────────────────────
        match check_addin_restrictions(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("EXO-ADDINS-001 check failed: {}", e);
                findings.push(
                    Finding::new(
                        "EXO-ADDINS-001",
                        "Exchange Online",
                        "Client Access",
                        "User Add-In Installation",
                        "Verify users cannot install unapproved add-ins",
                    )
                    .status(FindingStatus::Review)
                    .severity(registry.get_severity("EXO-ADDINS-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("User add-in installation restricted")
                    .remediation("Restrict add-in installation via Exchange admin center > Org settings > User owned apps and services.")
                    .build(),
                );
            }
        }

        // ── DNS Checks (SPF, DKIM, DMARC) ──────────────────────────────
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        for domain in &tenant.verified_domains {
            // DNS-SPF-001
            match check_spf(&resolver, domain, registry).await {
                Ok(f) => findings.push(f),
                Err(e) => {
                    tracing::warn!("DNS-SPF-001 check failed for {}: {}", domain, e);
                    findings.push(
                        Finding::new(
                            "DNS-SPF-001",
                            "Exchange Online",
                            "Email Authentication",
                            "SPF Record",
                            format!("Verify SPF record exists for domain {}", domain),
                        )
                        .status(FindingStatus::Review)
                        .severity(registry.get_severity("DNS-SPF-001"))
                        .current_value(format!("Error checking {}: {}", domain, e))
                        .expected_value("Valid SPF record (v=spf1 ...)")
                        .remediation(format!(
                            "Add an SPF TXT record for {} (e.g., v=spf1 include:spf.protection.outlook.com -all)",
                            domain
                        ))
                        .build(),
                    );
                }
            }

            // DNS-DKIM-001
            match check_dkim(&resolver, domain, registry).await {
                Ok(f) => findings.push(f),
                Err(e) => {
                    tracing::warn!("DNS-DKIM-001 check failed for {}: {}", domain, e);
                    findings.push(
                        Finding::new(
                            "DNS-DKIM-001",
                            "Exchange Online",
                            "Email Authentication",
                            "DKIM Configuration",
                            format!("Verify DKIM is configured for domain {}", domain),
                        )
                        .status(FindingStatus::Review)
                        .severity(registry.get_severity("DNS-DKIM-001"))
                        .current_value(format!("Error checking {}: {}", domain, e))
                        .expected_value("DKIM selectors configured (selector1/selector2)")
                        .remediation(format!(
                            "Enable DKIM signing for {} in Exchange admin center > Authentication > DKIM.",
                            domain
                        ))
                        .build(),
                    );
                }
            }

            // DNS-DMARC-001
            match check_dmarc(&resolver, domain, registry).await {
                Ok(f) => findings.push(f),
                Err(e) => {
                    tracing::warn!("DNS-DMARC-001 check failed for {}: {}", domain, e);
                    findings.push(
                        Finding::new(
                            "DNS-DMARC-001",
                            "Exchange Online",
                            "Email Authentication",
                            "DMARC Policy",
                            format!("Verify DMARC record with enforce policy for domain {}", domain),
                        )
                        .status(FindingStatus::Review)
                        .severity(registry.get_severity("DNS-DMARC-001"))
                        .current_value(format!("Error checking {}: {}", domain, e))
                        .expected_value("DMARC record with p=reject or p=quarantine")
                        .remediation(format!(
                            "Add a DMARC TXT record for _dmarc.{} (e.g., v=DMARC1; p=reject; rua=mailto:dmarc@{})",
                            domain, domain
                        ))
                        .build(),
                    );
                }
            }
        }

        // Post-process: replace Review findings (EXO API failures) with Secure Score data
        let secure_score_map: std::collections::HashMap<&str, &[&str]> = [
            (
                "EXO-AUDIT-001",
                &["AdminAuditLogEnabled", "AuditEnabled", "TurnOnAuditLog"][..],
            ),
            (
                "EXO-EXTTAG-001",
                &["ExternalSenderTagging", "OneStepEnabled"][..],
            ),
            (
                "EXO-FORWARD-001",
                &["BlockAutoForwardedEmail", "AutoForwardedEmail"][..],
            ),
            ("EXO-MAILTIPS-001", &["MailTipsEnabled", "MailTips"][..]),
            (
                "EXO-TRANSPORT-001",
                &["ReviewTransportRules", "TransportRules"][..],
            ),
            ("EXO-CONNFILTER-001", &["ConnectionFilterIpAllowList"][..]),
            (
                "EXO-ADDINS-001",
                &["BlockAddins", "UserOwnedAppsAndServicesEnabled"][..],
            ),
            ("EXO-OWA-001", &["OWAMailboxPolicy"][..]),
            ("EXO-SHARING-001", &["CalendarSharing", "SharingPolicy"][..]),
            (
                "EXO-SHAREDMBX-001",
                &["SharedMailbox", "SharedMailboxSignIn"][..],
            ),
            (
                "EXO-LOCKBOX-001",
                &["CustomerLockbox", "CustomerLockBoxEnabled"][..],
            ),
            (
                "EXO-AUDIT-002",
                &["AdminAuditLogConfig", "AdminAuditLog"][..],
            ),
            ("EXO-AUTH-001", &["ModernAuth", "ModernAuthentication"][..]),
            (
                "EXO-AUTH-002",
                &["BasicAuth", "BasicAuthentication", "BlockBasicAuth"][..],
            ),
        ]
        .into_iter()
        .collect();

        for finding in &mut findings {
            if finding.status == FindingStatus::Review
                && finding.current_value.contains("Unable to query")
            {
                if let Some(control_names) = secure_score_map.get(finding.check_id.as_str()) {
                    let (new_status, new_value) = evaluate_from_secure_score(
                        &secure_score_controls,
                        control_names,
                        &finding.setting,
                    );
                    if new_status != FindingStatus::Review {
                        finding.status = new_status;
                        finding.current_value = new_value;
                    }
                }
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

// ─── Individual Check Implementations ────────────────────────────────────────

/// EXO-AUTH-001: Modern Authentication
async fn check_modern_auth(graph: &GraphClient, registry: &ControlRegistry) -> Result<Finding> {
    let org: serde_json::Value = graph.get_json("/v1.0/organization").await?;
    let org_value = org["value"]
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow::anyhow!("No organization data returned"))?;

    // Check if OAuth2 is enabled (onPremisesSyncEnabled is unrelated, but
    // the presence of the organization object with a valid tenant indicates
    // that modern auth / OAuth2 is in use since Graph API itself requires it).
    // Also check for any legacy auth signals.
    let on_premises = org_value["onPremisesSyncEnabled"]
        .as_bool()
        .unwrap_or(false);

    // Modern auth is effectively always enabled for Exchange Online tenants
    // that are accessible via Graph API. The key concern is whether legacy
    // protocols are additionally allowed.
    let status = FindingStatus::Pass;
    let current = if on_premises {
        String::from("Modern authentication enabled (hybrid with on-premises sync)")
    } else {
        String::from("Modern authentication enabled (cloud-only)")
    };

    Ok(Finding::new(
        "EXO-AUTH-001",
        "Exchange Online",
        "Authentication",
        "Modern Authentication",
        "Verify modern authentication is enabled for Exchange Online",
    )
    .status(status)
    .severity(registry.get_severity("EXO-AUTH-001"))
    .current_value(current)
    .expected_value("Modern authentication enabled")
    .remediation(
        "Modern authentication is enabled by default for Exchange Online. \
         Ensure no authentication policies re-enable basic auth protocols.",
    )
    .build())
}

/// EXO-AUTH-002: Basic Authentication Disabled (via Security Defaults)
async fn check_basic_auth_disabled(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    // Check security defaults - if enabled, basic auth is blocked
    let policy: serde_json::Value = graph
        .get_json("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy")
        .await?;

    let sec_defaults_enabled = policy["isEnabled"].as_bool().unwrap_or(false);

    let (status, current) = if sec_defaults_enabled {
        (
            FindingStatus::Pass,
            String::from("Security defaults enabled - basic authentication is blocked"),
        )
    } else {
        // Security defaults disabled does not necessarily mean basic auth is
        // allowed (could be blocked via conditional access), but it is a risk signal.
        (
            FindingStatus::Warning,
            String::from(
                "Security defaults disabled - basic auth may be allowed unless blocked by conditional access",
            ),
        )
    };

    Ok(Finding::new(
        "EXO-AUTH-002",
        "Exchange Online",
        "Authentication",
        "Basic Authentication Disabled",
        "Verify basic authentication is disabled via security defaults or conditional access",
    )
    .status(status)
    .severity(registry.get_severity("EXO-AUTH-002"))
    .current_value(current)
    .expected_value("Basic authentication blocked (security defaults or conditional access)")
    .remediation(
        "Enable security defaults or create a conditional access policy to block legacy authentication. \
         Navigate to Entra ID > Properties > Manage security defaults.",
    )
    .build())
}

/// EXO-AUDIT-001: Mailbox Auditing
async fn check_mailbox_auditing(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    // Try to check via Exchange admin API
    let url = exo_admin_url(&tenant.tenant_id, "OrganizationConfig");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let audit_disabled = config["AuditDisabled"].as_bool().unwrap_or(false);

            let (status, current) = if !audit_disabled {
                (
                    FindingStatus::Pass,
                    String::from("Mailbox auditing is enabled organization-wide"),
                )
            } else {
                (
                    FindingStatus::Fail,
                    String::from("Mailbox auditing is disabled at the organization level"),
                )
            };

            Ok(Finding::new(
                "EXO-AUDIT-001",
                "Exchange Online",
                "Auditing",
                "Mailbox Auditing",
                "Verify mailbox auditing is enabled organization-wide",
            )
            .status(status)
            .severity(registry.get_severity("EXO-AUDIT-001"))
            .current_value(current)
            .expected_value("Mailbox auditing enabled (AuditDisabled = false)")
            .remediation(
                "Enable mailbox auditing via PowerShell: Set-OrganizationConfig -AuditDisabled $false",
            )
            .build())
        }
        Err(_) => {
            // Exchange admin API not available; mailbox auditing has been
            // enabled by default since January 2019 for all Exchange Online orgs.
            Ok(Finding::new(
                "EXO-AUDIT-001",
                "Exchange Online",
                "Auditing",
                "Mailbox Auditing",
                "Verify mailbox auditing is enabled organization-wide",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("EXO-AUDIT-001"))
            .current_value(
                "Unable to query Exchange admin API. Mailbox auditing is enabled by default since 2019.",
            )
            .expected_value("Mailbox auditing enabled (AuditDisabled = false)")
            .remediation(
                "Verify via PowerShell: Get-OrganizationConfig | FL AuditDisabled. \
                 Should return False.",
            )
            .build())
        }
    }
}

/// EXO-AUDIT-002: Admin Audit Log
async fn check_admin_audit_log(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let url = exo_admin_url(&tenant.tenant_id, "AdminAuditLogConfig");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let enabled = config["AdminAuditLogEnabled"].as_bool().unwrap_or(false);

            let (status, current) = if enabled {
                (
                    FindingStatus::Pass,
                    String::from("Admin audit logging is enabled"),
                )
            } else {
                (
                    FindingStatus::Fail,
                    String::from("Admin audit logging is disabled"),
                )
            };

            Ok(Finding::new(
                "EXO-AUDIT-002",
                "Exchange Online",
                "Auditing",
                "Admin Audit Log",
                "Verify admin audit logging is enabled",
            )
            .status(status)
            .severity(registry.get_severity("EXO-AUDIT-002"))
            .current_value(current)
            .expected_value("Admin audit log enabled")
            .remediation(
                "Admin audit logging is on by default in Exchange Online and cannot be turned off. \
                 Verify via PowerShell: Get-AdminAuditLogConfig | FL AdminAuditLogEnabled",
            )
            .build())
        }
        Err(_) => Ok(Finding::new(
            "EXO-AUDIT-002",
            "Exchange Online",
            "Auditing",
            "Admin Audit Log",
            "Verify admin audit logging is enabled",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("EXO-AUDIT-002"))
        .current_value("Unable to query Exchange admin API. Manual verification needed.")
        .expected_value("Admin audit log enabled")
        .remediation("Verify via PowerShell: Get-AdminAuditLogConfig | FL AdminAuditLogEnabled")
        .build()),
    }
}

/// EXO-EXTTAG-001: External Sender Tagging
async fn check_external_sender_tagging(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let url = exo_admin_url(&tenant.tenant_id, "ExternalInOutlook");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let enabled = config["Enabled"].as_bool().unwrap_or(false);

            let (status, current) = if enabled {
                (
                    FindingStatus::Pass,
                    String::from("External sender tagging is enabled"),
                )
            } else {
                (
                    FindingStatus::Fail,
                    String::from("External sender tagging is not enabled"),
                )
            };

            Ok(Finding::new(
                "EXO-EXTTAG-001",
                "Exchange Online",
                "Mail Flow",
                "External Sender Tagging",
                "Verify external sender tagging is enabled to flag emails from outside the organization",
            )
            .status(status)
            .severity(registry.get_severity("EXO-EXTTAG-001"))
            .current_value(current)
            .expected_value("External sender tagging enabled")
            .remediation(
                "Enable via Exchange Online PowerShell: Set-ExternalInOutlook -Enabled $true",
            )
            .build())
        }
        Err(_) => {
            Ok(Finding::new(
                "EXO-EXTTAG-001",
                "Exchange Online",
                "Mail Flow",
                "External Sender Tagging",
                "Verify external sender tagging is enabled to flag emails from outside the organization",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("EXO-EXTTAG-001"))
            .current_value(
                "Unable to query Exchange admin API. Manual verification needed.",
            )
            .expected_value("External sender tagging enabled")
            .remediation(
                "Verify via PowerShell: Get-ExternalInOutlook | FL Enabled. \
                 Enable with: Set-ExternalInOutlook -Enabled $true",
            )
            .build())
        }
    }
}

/// EXO-FORWARD-001: Auto-Forwarding to External Recipients
async fn check_auto_forwarding(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    // Check remote domains for auto-forwarding setting
    let url = exo_admin_url(&tenant.tenant_id, "RemoteDomain");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let domains = config["value"].as_array();
            let mut forwarding_allowed = false;
            let mut offending_domains: Vec<String> = Vec::new();

            if let Some(domains) = domains {
                for domain in domains {
                    let auto_forward = domain["AutoForwardEnabled"].as_bool().unwrap_or(false);
                    if auto_forward {
                        forwarding_allowed = true;
                        let name = domain["DomainName"]
                            .as_str()
                            .unwrap_or("Unknown")
                            .to_string();
                        offending_domains.push(name);
                    }
                }
            }

            let (status, current) = if forwarding_allowed {
                (
                    FindingStatus::Fail,
                    format!(
                        "Auto-forwarding is allowed for remote domains: {}",
                        offending_domains.join(", ")
                    ),
                )
            } else {
                (
                    FindingStatus::Pass,
                    String::from(
                        "Auto-forwarding to external recipients is disabled on all remote domains",
                    ),
                )
            };

            Ok(Finding::new(
                "EXO-FORWARD-001",
                "Exchange Online",
                "Mail Flow",
                "Auto-Forwarding to External Recipients",
                "Verify automatic forwarding to external recipients is disabled",
            )
            .status(status)
            .severity(registry.get_severity("EXO-FORWARD-001"))
            .current_value(current)
            .expected_value("Auto-forwarding to external recipients disabled")
            .remediation(
                "Disable auto-forwarding on the default remote domain: \
                 Set-RemoteDomain Default -AutoForwardEnabled $false",
            )
            .build())
        }
        Err(_) => Ok(Finding::new(
            "EXO-FORWARD-001",
            "Exchange Online",
            "Mail Flow",
            "Auto-Forwarding to External Recipients",
            "Verify automatic forwarding to external recipients is disabled",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("EXO-FORWARD-001"))
        .current_value("Unable to query Exchange admin API. Manual verification needed.")
        .expected_value("Auto-forwarding to external recipients disabled")
        .remediation(
            "Verify via PowerShell: Get-RemoteDomain | FL DomainName, AutoForwardEnabled. \
                 Disable with: Set-RemoteDomain Default -AutoForwardEnabled $false",
        )
        .build()),
    }
}

/// EXO-LOCKBOX-001: Customer Lockbox (E5 required)
async fn check_customer_lockbox(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    if !tenant.has_e5() {
        return Ok(Finding::new(
            "EXO-LOCKBOX-001",
            "Exchange Online",
            "Data Protection",
            "Customer Lockbox",
            "Verify Customer Lockbox is enabled for Microsoft support access requests",
        )
        .status(FindingStatus::NotLicensed)
        .severity(registry.get_severity("EXO-LOCKBOX-001"))
        .current_value("E5 or equivalent license not detected")
        .expected_value("Customer Lockbox enabled (requires E5)")
        .remediation(
            "Customer Lockbox requires Microsoft 365 E5 or Office 365 E5 licensing. \
             Upgrade licensing to enable this feature.",
        )
        .build());
    }

    let url = exo_admin_url(&tenant.tenant_id, "OrganizationConfig");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let lockbox_enabled = config["CustomerLockBoxEnabled"]
                .as_bool()
                .unwrap_or(false);

            let (status, current) = if lockbox_enabled {
                (
                    FindingStatus::Pass,
                    String::from("Customer Lockbox is enabled"),
                )
            } else {
                (
                    FindingStatus::Fail,
                    String::from("Customer Lockbox is not enabled"),
                )
            };

            Ok(Finding::new(
                "EXO-LOCKBOX-001",
                "Exchange Online",
                "Data Protection",
                "Customer Lockbox",
                "Verify Customer Lockbox is enabled for Microsoft support access requests",
            )
            .status(status)
            .severity(registry.get_severity("EXO-LOCKBOX-001"))
            .current_value(current)
            .expected_value("Customer Lockbox enabled")
            .remediation(
                "Enable Customer Lockbox in Microsoft 365 admin center > Settings > Org settings > Security & privacy > Customer Lockbox.",
            )
            .build())
        }
        Err(_) => {
            Ok(Finding::new(
                "EXO-LOCKBOX-001",
                "Exchange Online",
                "Data Protection",
                "Customer Lockbox",
                "Verify Customer Lockbox is enabled for Microsoft support access requests",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("EXO-LOCKBOX-001"))
            .current_value(
                "Unable to query Exchange admin API. Manual verification needed.",
            )
            .expected_value("Customer Lockbox enabled")
            .remediation(
                "Verify in Microsoft 365 admin center > Settings > Org settings > Security & privacy > Customer Lockbox.",
            )
            .build())
        }
    }
}

/// EXO-MAILTIPS-001: MailTips for External Recipients
async fn check_mailtips(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let url = exo_admin_url(&tenant.tenant_id, "OrganizationConfig");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let mailtips_enabled = config["MailTipsExternalRecipientsTipsEnabled"]
                .as_bool()
                .unwrap_or(false);
            let mailtips_all = config["MailTipsAllTipsEnabled"].as_bool().unwrap_or(false);

            let (status, current) = if mailtips_enabled && mailtips_all {
                (
                    FindingStatus::Pass,
                    String::from("MailTips enabled including external recipient warnings"),
                )
            } else if mailtips_enabled {
                (
                    FindingStatus::Warning,
                    String::from(
                        "External recipient MailTips enabled but not all MailTips are enabled",
                    ),
                )
            } else {
                (
                    FindingStatus::Fail,
                    String::from("MailTips for external recipients are not enabled"),
                )
            };

            Ok(Finding::new(
                "EXO-MAILTIPS-001",
                "Exchange Online",
                "Mail Flow",
                "MailTips External Recipients",
                "Verify MailTips are enabled to warn users when emailing external recipients",
            )
            .status(status)
            .severity(registry.get_severity("EXO-MAILTIPS-001"))
            .current_value(current)
            .expected_value("MailTips for external recipients enabled")
            .remediation(
                "Enable via PowerShell: Set-OrganizationConfig -MailTipsAllTipsEnabled $true \
                 -MailTipsExternalRecipientsTipsEnabled $true",
            )
            .build())
        }
        Err(_) => Ok(Finding::new(
            "EXO-MAILTIPS-001",
            "Exchange Online",
            "Mail Flow",
            "MailTips External Recipients",
            "Verify MailTips are enabled to warn users when emailing external recipients",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("EXO-MAILTIPS-001"))
        .current_value("Unable to query Exchange admin API. Manual verification needed.")
        .expected_value("MailTips for external recipients enabled")
        .remediation("Verify via PowerShell: Get-OrganizationConfig | FL MailTips*")
        .build()),
    }
}

/// EXO-OWA-001: OWA Mailbox Policy Restrictions
async fn check_owa_policy(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let url = exo_admin_url(&tenant.tenant_id, "OwaMailboxPolicy");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let policies = config["value"].as_array();
            let mut issues: Vec<String> = Vec::new();

            if let Some(policies) = policies {
                for policy in policies {
                    let name = policy["Name"]
                        .as_str()
                        .unwrap_or("Unknown")
                        .to_string();

                    // Check for risky settings that should be disabled
                    if policy["AdditionalStorageProvidersAvailable"]
                        .as_bool()
                        .unwrap_or(true)
                    {
                        issues.push(format!(
                            "{}: AdditionalStorageProvidersAvailable is enabled",
                            name
                        ));
                    }
                    if policy["ExternalSPMySiteHostURL"]
                        .as_str()
                        .map(|s| !s.is_empty())
                        .unwrap_or(false)
                    {
                        issues.push(format!(
                            "{}: ExternalSPMySiteHostURL is configured",
                            name
                        ));
                    }
                    if policy["ReferenceAttachmentsEnabled"]
                        .as_bool()
                        .unwrap_or(false)
                    {
                        // This is actually OK in many environments; only flag
                        // AdditionalStorageProviders as the primary concern.
                    }
                }
            }

            let (status, current) = if issues.is_empty() {
                (
                    FindingStatus::Pass,
                    String::from("OWA mailbox policies are appropriately restricted"),
                )
            } else {
                (
                    FindingStatus::Warning,
                    format!("OWA policy issues: {}", issues.join("; ")),
                )
            };

            Ok(Finding::new(
                "EXO-OWA-001",
                "Exchange Online",
                "Client Access",
                "OWA Mailbox Policy",
                "Verify OWA mailbox policy restricts risky features",
            )
            .status(status)
            .severity(registry.get_severity("EXO-OWA-001"))
            .current_value(current)
            .expected_value(
                "OWA policy restricts external storage providers and risky features",
            )
            .remediation(
                "Restrict OWA policies via PowerShell: \
                 Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default \
                 -AdditionalStorageProvidersAvailable $false",
            )
            .build())
        }
        Err(_) => {
            Ok(Finding::new(
                "EXO-OWA-001",
                "Exchange Online",
                "Client Access",
                "OWA Mailbox Policy",
                "Verify OWA mailbox policy restricts risky features",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("EXO-OWA-001"))
            .current_value(
                "Unable to query Exchange admin API. Manual verification needed.",
            )
            .expected_value(
                "OWA policy restricts external storage providers and risky features",
            )
            .remediation(
                "Verify via PowerShell: Get-OwaMailboxPolicy | FL Name, AdditionalStorageProvidersAvailable",
            )
            .build())
        }
    }
}

/// EXO-SHAREDMBX-001: Shared Mailbox Sign-In Disabled
async fn check_shared_mailbox_signin(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    // Get shared mailboxes via Graph - they are users with mailboxSettings
    // We query users that have a shared mailbox (recipientTypeDetails)
    // Via Graph, we look for users where the mailbox type is shared and
    // check if their account is sign-in enabled.
    let users: Vec<serde_json::Value> = graph
        .get_all::<serde_json::Value>(
            "/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,mailboxSettings&$filter=assignedLicenses/$count eq 0&$count=true",
        )
        .await
        .unwrap_or_default();

    // If we cannot distinguish shared mailboxes reliably via Graph,
    // provide a summary finding.
    if users.is_empty() {
        return Ok(vec![Finding::new(
            "EXO-SHAREDMBX-001",
            "Exchange Online",
            "Mailbox Security",
            "Shared Mailbox Direct Sign-In",
            "Verify shared mailboxes have direct sign-in disabled",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("EXO-SHAREDMBX-001"))
        .current_value(
            "No unlicensed users found or unable to enumerate shared mailboxes via Graph API",
        )
        .expected_value("All shared mailboxes have sign-in disabled")
        .remediation(
            "Verify via PowerShell: Get-Mailbox -RecipientTypeDetails SharedMailbox | \
             Get-MsolUser | Where {$_.BlockCredential -eq $false}",
        )
        .build()]);
    }

    let mut enabled_shared: Vec<String> = Vec::new();
    for user in &users {
        let account_enabled = user["accountEnabled"].as_bool().unwrap_or(false);
        if account_enabled {
            let upn = user["userPrincipalName"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string();
            enabled_shared.push(upn);
        }
    }

    let (status, current) =
        if enabled_shared.is_empty() {
            (
                FindingStatus::Pass,
                String::from("No shared/unlicensed mailboxes with sign-in enabled found"),
            )
        } else {
            (
                FindingStatus::Warning,
                format!(
                "{} unlicensed account(s) with sign-in enabled (may include shared mailboxes): {}",
                enabled_shared.len(),
                if enabled_shared.len() <= 5 {
                    enabled_shared.join(", ")
                } else {
                    let preview: Vec<String> = enabled_shared.iter().take(5).cloned().collect();
                    format!("{} and {} more", preview.join(", "), enabled_shared.len() - 5)
                }
            ),
            )
        };

    let mut finding = Finding::new(
        "EXO-SHAREDMBX-001",
        "Exchange Online",
        "Mailbox Security",
        "Shared Mailbox Direct Sign-In",
        "Verify shared mailboxes have direct sign-in disabled",
    )
    .status(status)
    .severity(registry.get_severity("EXO-SHAREDMBX-001"))
    .current_value(current)
    .expected_value("All shared mailboxes have sign-in disabled")
    .remediation(
        "Disable sign-in for shared mailboxes: \
         Set-MsolUser -UserPrincipalName <UPN> -BlockCredential $true",
    );

    if !enabled_shared.is_empty() {
        finding = finding.affected_resources(enabled_shared);
    }

    Ok(vec![finding.build()])
}

/// EXO-SHARING-001: Calendar Sharing Restrictions
async fn check_calendar_sharing(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let url = exo_admin_url(&tenant.tenant_id, "SharingPolicy");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let policies = config["value"].as_array();
            let mut external_sharing_unrestricted = false;

            if let Some(policies) = policies {
                for policy in policies {
                    let domains = policy["Domains"].as_array();
                    let default_policy = policy["Default"].as_bool().unwrap_or(false);
                    if default_policy {
                        if let Some(domains) = domains {
                            for domain_entry in domains {
                                let action = domain_entry
                                    .as_str()
                                    .or_else(|| domain_entry["Action"].as_str())
                                    .unwrap_or("");
                                if action.contains("CalendarSharingFreeBusyDetail")
                                    || action.contains("CalendarSharingFreeBusySimple")
                                {
                                    // These are acceptable levels of sharing
                                } else if action.contains("Calendar") {
                                    external_sharing_unrestricted = true;
                                }
                            }
                        }
                        // If domains list contains "*" with full details, it is too broad
                        let enabled = policy["Enabled"].as_bool().unwrap_or(true);
                        if enabled {
                            let domains_str =
                                serde_json::to_string(&policy["Domains"]).unwrap_or_default();
                            if domains_str.contains("*:CalendarSharingFreeBusyReviewer")
                                || domains_str.contains("*:CalendarSharingFreeBusyDetail")
                            {
                                external_sharing_unrestricted = true;
                            }
                        }
                    }
                }
            }

            let (status, current) = if external_sharing_unrestricted {
                (
                    FindingStatus::Warning,
                    String::from(
                        "Calendar sharing allows detailed free/busy or more to external recipients",
                    ),
                )
            } else {
                (
                    FindingStatus::Pass,
                    String::from("Calendar sharing is appropriately restricted"),
                )
            };

            Ok(Finding::new(
                "EXO-SHARING-001",
                "Exchange Online",
                "Sharing",
                "Calendar Sharing Policy",
                "Verify calendar sharing with external recipients is restricted",
            )
            .status(status)
            .severity(registry.get_severity("EXO-SHARING-001"))
            .current_value(current)
            .expected_value("Calendar sharing restricted to free/busy only for external recipients")
            .remediation(
                "Restrict sharing policies via PowerShell: \
                 Set-SharingPolicy -Identity 'Default Sharing Policy' \
                 -Domains 'Anonymous:CalendarSharingFreeBusySimple'",
            )
            .build())
        }
        Err(_) => Ok(Finding::new(
            "EXO-SHARING-001",
            "Exchange Online",
            "Sharing",
            "Calendar Sharing Policy",
            "Verify calendar sharing with external recipients is restricted",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("EXO-SHARING-001"))
        .current_value("Unable to query Exchange admin API. Manual verification needed.")
        .expected_value("Calendar sharing restricted to free/busy only for external recipients")
        .remediation("Verify via PowerShell: Get-SharingPolicy | FL Name, Domains, Enabled")
        .build()),
    }
}

/// EXO-TRANSPORT-001: Transport Rules Review
async fn check_transport_rules(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let url = exo_admin_url(&tenant.tenant_id, "TransportRule");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let rules = config["value"].as_array();
            let mut rule_count = 0usize;
            let mut risky_rules: Vec<String> = Vec::new();

            if let Some(rules) = rules {
                rule_count = rules.len();
                for rule in rules {
                    let name = rule["Name"].as_str().unwrap_or("Unknown").to_string();
                    let state = rule["State"].as_str().unwrap_or("Enabled");

                    if state != "Enabled" {
                        continue;
                    }

                    // Flag rules that bypass spam filtering or set SCL to -1
                    let set_scl = rule["SetSCL"].as_i64();
                    if set_scl == Some(-1) {
                        risky_rules.push(format!(
                            "{}: sets SCL to -1 (bypasses spam filtering)",
                            name
                        ));
                    }

                    // Flag rules that modify headers to bypass filtering
                    let set_header = rule["SetHeaderName"].as_str().unwrap_or("");
                    if set_header
                        .to_lowercase()
                        .contains("x-ms-exchange-organization-authas")
                    {
                        risky_rules.push(format!("{}: modifies authentication header", name));
                    }
                }
            }

            let (status, current) = if risky_rules.is_empty() {
                (
                    FindingStatus::Pass,
                    format!(
                        "{} transport rule(s) found, none with risky configurations",
                        rule_count
                    ),
                )
            } else {
                (
                    FindingStatus::Warning,
                    format!(
                        "{} transport rule(s) found, {} with risky configurations: {}",
                        rule_count,
                        risky_rules.len(),
                        risky_rules.join("; ")
                    ),
                )
            };

            Ok(Finding::new(
                "EXO-TRANSPORT-001",
                "Exchange Online",
                "Mail Flow",
                "Transport Rules",
                "Review transport rules for security implications",
            )
            .status(status)
            .severity(registry.get_severity("EXO-TRANSPORT-001"))
            .current_value(current)
            .expected_value("No transport rules that bypass security filtering")
            .remediation(
                "Review transport rules in Exchange admin center > Mail flow > Rules. \
                 Remove or disable rules that set SCL to -1 or bypass spam filtering.",
            )
            .build())
        }
        Err(_) => Ok(Finding::new(
            "EXO-TRANSPORT-001",
            "Exchange Online",
            "Mail Flow",
            "Transport Rules",
            "Review transport rules for security implications",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("EXO-TRANSPORT-001"))
        .current_value("Unable to query Exchange admin API. Manual verification needed.")
        .expected_value("No transport rules that bypass security filtering")
        .remediation("Verify via PowerShell: Get-TransportRule | FL Name, State, SetSCL")
        .build()),
    }
}

/// EXO-CONNFILTER-001: Connection Filter IP Allow List
async fn check_connection_filter(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let url = exo_admin_url(&tenant.tenant_id, "HostedConnectionFilterPolicy");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let policies = config["value"].as_array();
            let mut total_allowed_ips = 0usize;
            let mut ip_list: Vec<String> = Vec::new();

            if let Some(policies) = policies {
                for policy in policies {
                    if let Some(ips) = policy["IPAllowList"].as_array() {
                        for ip in ips {
                            if let Some(ip_str) = ip.as_str() {
                                ip_list.push(ip_str.to_string());
                                total_allowed_ips += 1;
                            }
                        }
                    }
                }
            }

            let (status, current) = if total_allowed_ips == 0 {
                (
                    FindingStatus::Pass,
                    String::from("Connection filter IP allow list is empty"),
                )
            } else if total_allowed_ips <= 5 {
                (
                    FindingStatus::Warning,
                    format!(
                        "{} IP(s) in allow list: {}",
                        total_allowed_ips,
                        ip_list.join(", ")
                    ),
                )
            } else {
                (
                    FindingStatus::Fail,
                    format!(
                        "{} IP(s) in allow list - this is overly broad and bypasses spam filtering",
                        total_allowed_ips
                    ),
                )
            };

            let mut finding = Finding::new(
                "EXO-CONNFILTER-001",
                "Exchange Online",
                "Mail Flow",
                "Connection Filter IP Allow List",
                "Verify the connection filter IP allow list is not overly broad",
            )
            .status(status)
            .severity(registry.get_severity("EXO-CONNFILTER-001"))
            .current_value(current)
            .expected_value("Connection filter IP allow list is empty or minimal")
            .remediation(
                "Review and minimize the IP allow list in Exchange admin center > \
                 Mail flow > Connection filtering. Remove any unnecessary entries.",
            );

            if !ip_list.is_empty() {
                finding = finding.affected_resources(ip_list);
            }

            Ok(finding.build())
        }
        Err(_) => Ok(Finding::new(
            "EXO-CONNFILTER-001",
            "Exchange Online",
            "Mail Flow",
            "Connection Filter IP Allow List",
            "Verify the connection filter IP allow list is not overly broad",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("EXO-CONNFILTER-001"))
        .current_value("Unable to query Exchange admin API. Manual verification needed.")
        .expected_value("Connection filter IP allow list is empty or minimal")
        .remediation("Verify via PowerShell: Get-HostedConnectionFilterPolicy | FL IPAllowList")
        .build()),
    }
}

/// EXO-ADDINS-001: User Add-In Restrictions
async fn check_addin_restrictions(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    // Check OWA mailbox policy for add-in settings and also try the
    // role assignment policy via Exchange admin API
    let url = exo_admin_url(&tenant.tenant_id, "RoleAssignmentPolicy");
    match graph.exo_get_json(&url).await {
        Ok(config) => {
            let policies = config["value"].as_array();
            let mut user_addins_allowed = false;

            if let Some(policies) = policies {
                for policy in policies {
                    let is_default = policy["IsDefault"].as_bool().unwrap_or(false);
                    if is_default {
                        if let Some(roles) = policy["AssignedRoles"].as_array() {
                            for role in roles {
                                let role_name = role.as_str().unwrap_or("");
                                if role_name.contains("My Custom Apps")
                                    || role_name.contains("My Marketplace Apps")
                                    || role_name.contains("My ReadWriteMailbox Apps")
                                {
                                    user_addins_allowed = true;
                                }
                            }
                        }
                    }
                }
            }

            let (status, current) = if user_addins_allowed {
                (
                    FindingStatus::Warning,
                    String::from("Users can install add-ins via default role assignment policy"),
                )
            } else {
                (
                    FindingStatus::Pass,
                    String::from(
                        "User add-in installation is restricted in the default role assignment policy",
                    ),
                )
            };

            Ok(Finding::new(
                "EXO-ADDINS-001",
                "Exchange Online",
                "Client Access",
                "User Add-In Installation",
                "Verify users cannot install unapproved add-ins",
            )
            .status(status)
            .severity(registry.get_severity("EXO-ADDINS-001"))
            .current_value(current)
            .expected_value("User add-in installation restricted")
            .remediation(
                "Remove 'My Custom Apps' and 'My Marketplace Apps' roles from the default \
                 role assignment policy via PowerShell: \
                 Set-RoleAssignmentPolicy -Identity 'Default Role Assignment Policy' \
                 -Roles @{Remove='My Custom Apps','My Marketplace Apps'}",
            )
            .build())
        }
        Err(_) => Ok(Finding::new(
            "EXO-ADDINS-001",
            "Exchange Online",
            "Client Access",
            "User Add-In Installation",
            "Verify users cannot install unapproved add-ins",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("EXO-ADDINS-001"))
        .current_value("Unable to query Exchange admin API. Manual verification needed.")
        .expected_value("User add-in installation restricted")
        .remediation(
            "Verify via PowerShell: Get-RoleAssignmentPolicy | Where {$_.IsDefault} | \
                 FL AssignedRoles",
        )
        .build()),
    }
}

// ─── DNS Check Implementations ──────────────────────────────────────────────

/// DNS-SPF-001: SPF Record Check
async fn check_spf(
    resolver: &TokioAsyncResolver,
    domain: &str,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let txt_records = resolver.txt_lookup(domain).await;

    match txt_records {
        Ok(records) => {
            let mut spf_record: Option<String> = None;
            for record in records.iter() {
                let txt = record.to_string();
                if txt.starts_with("v=spf1") {
                    spf_record = Some(txt);
                    break;
                }
            }

            let (status, current) = if let Some(ref spf) = spf_record {
                // Check for -all (hard fail) vs ~all (soft fail) vs ?all (neutral)
                if spf.contains("-all") {
                    (
                        FindingStatus::Pass,
                        format!("SPF record found with hard fail (-all): {}", spf),
                    )
                } else if spf.contains("~all") {
                    (
                        FindingStatus::Warning,
                        format!(
                            "SPF record found with soft fail (~all) - consider using -all: {}",
                            spf
                        ),
                    )
                } else {
                    (
                        FindingStatus::Warning,
                        format!("SPF record found but does not use -all or ~all: {}", spf),
                    )
                }
            } else {
                (
                    FindingStatus::Fail,
                    format!("No SPF record found for domain {}", domain),
                )
            };

            Ok(Finding::new(
                "DNS-SPF-001",
                "Exchange Online",
                "Email Authentication",
                "SPF Record",
                format!("Verify SPF record exists for domain {}", domain),
            )
            .status(status)
            .severity(registry.get_severity("DNS-SPF-001"))
            .current_value(current)
            .expected_value("Valid SPF record with -all (hard fail)")
            .remediation(format!(
                "Add or update the SPF TXT record for {}: v=spf1 include:spf.protection.outlook.com -all",
                domain
            ))
            .build())
        }
        Err(_) => Ok(Finding::new(
            "DNS-SPF-001",
            "Exchange Online",
            "Email Authentication",
            "SPF Record",
            format!("Verify SPF record exists for domain {}", domain),
        )
        .status(FindingStatus::Fail)
        .severity(registry.get_severity("DNS-SPF-001"))
        .current_value(format!("No TXT records found for domain {}", domain))
        .expected_value("Valid SPF record (v=spf1 ...)")
        .remediation(format!(
            "Add an SPF TXT record for {}: v=spf1 include:spf.protection.outlook.com -all",
            domain
        ))
        .build()),
    }
}

/// DNS-DKIM-001: DKIM Configuration Check
async fn check_dkim(
    resolver: &TokioAsyncResolver,
    domain: &str,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let selector1 = format!("selector1._domainkey.{}", domain);
    let selector2 = format!("selector2._domainkey.{}", domain);

    let sel1_cname = resolver
        .lookup(
            selector1.as_str(),
            trust_dns_resolver::proto::rr::RecordType::CNAME,
        )
        .await;
    let sel1_txt = resolver.txt_lookup(selector1.as_str()).await;

    let sel2_cname = resolver
        .lookup(
            selector2.as_str(),
            trust_dns_resolver::proto::rr::RecordType::CNAME,
        )
        .await;
    let sel2_txt = resolver.txt_lookup(selector2.as_str()).await;

    let sel1_found = sel1_cname.is_ok() || sel1_txt.is_ok();
    let sel2_found = sel2_cname.is_ok() || sel2_txt.is_ok();

    let (status, current) = if sel1_found && sel2_found {
        (
            FindingStatus::Pass,
            format!(
                "DKIM configured for {}: both selector1 and selector2 records found",
                domain
            ),
        )
    } else if sel1_found || sel2_found {
        (
            FindingStatus::Warning,
            format!(
                "DKIM partially configured for {}: {} found, {} missing",
                domain,
                if sel1_found { "selector1" } else { "selector2" },
                if sel1_found { "selector2" } else { "selector1" },
            ),
        )
    } else {
        (
            FindingStatus::Fail,
            format!(
                "DKIM not configured for {}: no selector records found",
                domain
            ),
        )
    };

    Ok(Finding::new(
        "DNS-DKIM-001",
        "Exchange Online",
        "Email Authentication",
        "DKIM Configuration",
        format!("Verify DKIM is configured for domain {}", domain),
    )
    .status(status)
    .severity(registry.get_severity("DNS-DKIM-001"))
    .current_value(current)
    .expected_value("DKIM selectors configured (selector1 and selector2)")
    .remediation(format!(
        "Enable DKIM signing for {} in Exchange admin center > Protection > DKIM, \
         or via PowerShell: New-DkimSigningConfig -DomainName {} -Enabled $true",
        domain, domain
    ))
    .build())
}

/// DNS-DMARC-001: DMARC Policy Check
async fn check_dmarc(
    resolver: &TokioAsyncResolver,
    domain: &str,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let dmarc_domain = format!("_dmarc.{}", domain);
    let txt_records = resolver.txt_lookup(dmarc_domain.as_str()).await;

    match txt_records {
        Ok(records) => {
            let mut dmarc_record: Option<String> = None;
            for record in records.iter() {
                let txt = record.to_string();
                if txt.starts_with("v=DMARC1") {
                    dmarc_record = Some(txt);
                    break;
                }
            }

            let (status, current) = if let Some(ref dmarc) = dmarc_record {
                // Parse the policy
                if dmarc.contains("p=reject") {
                    (
                        FindingStatus::Pass,
                        format!("DMARC record with reject policy: {}", dmarc),
                    )
                } else if dmarc.contains("p=quarantine") {
                    (
                        FindingStatus::Pass,
                        format!("DMARC record with quarantine policy: {}", dmarc),
                    )
                } else if dmarc.contains("p=none") {
                    (
                        FindingStatus::Warning,
                        format!(
                            "DMARC record exists but policy is 'none' (monitoring only): {}",
                            dmarc
                        ),
                    )
                } else {
                    (
                        FindingStatus::Warning,
                        format!("DMARC record found but policy is unclear: {}", dmarc),
                    )
                }
            } else {
                (
                    FindingStatus::Fail,
                    format!("No DMARC record found for domain {}", domain),
                )
            };

            Ok(Finding::new(
                "DNS-DMARC-001",
                "Exchange Online",
                "Email Authentication",
                "DMARC Policy",
                format!(
                    "Verify DMARC record with enforce policy for domain {}",
                    domain
                ),
            )
            .status(status)
            .severity(registry.get_severity("DNS-DMARC-001"))
            .current_value(current)
            .expected_value("DMARC record with p=reject or p=quarantine")
            .remediation(format!(
                "Add or update the DMARC TXT record for _dmarc.{}: \
                 v=DMARC1; p=reject; rua=mailto:dmarc-reports@{}; ruf=mailto:dmarc-reports@{}",
                domain, domain, domain
            ))
            .build())
        }
        Err(_) => Ok(Finding::new(
            "DNS-DMARC-001",
            "Exchange Online",
            "Email Authentication",
            "DMARC Policy",
            format!(
                "Verify DMARC record with enforce policy for domain {}",
                domain
            ),
        )
        .status(FindingStatus::Fail)
        .severity(registry.get_severity("DNS-DMARC-001"))
        .current_value(format!("No DMARC TXT record found for _dmarc.{}", domain))
        .expected_value("DMARC record with p=reject or p=quarantine")
        .remediation(format!(
            "Add a DMARC TXT record for _dmarc.{}: \
                 v=DMARC1; p=reject; rua=mailto:dmarc-reports@{}",
            domain, domain
        ))
        .build()),
    }
}
