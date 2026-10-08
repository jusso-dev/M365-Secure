//! Exchange Online checks. Every setting is read from Exchange Online cmdlets through the admin
//! REST API (`exo`), Microsoft Graph, or public DNS. A cmdlet that cannot be reached produces
//! `Unknown` with the reason; nothing is inferred from Secure Score.

pub mod apps;
pub mod audit;
pub mod auth;
pub mod dns;
pub mod exo;
pub mod mailflow;
pub mod tenant;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use super::{record, record_one, AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::Finding;
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use exo::Exo;

pub struct ExchangeModule;

const CATEGORY: &str = "Exchange Online";

#[async_trait]
impl AssessmentModule for ExchangeModule {
    fn name(&self) -> &str {
        "Exchange"
    }

    fn description(&self) -> &str {
        "Exchange Online authentication, auditing, mail flow, application access and email authentication (SPF, DKIM, DMARC)"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();
        let exo = Exo::new(graph, &tenant.tenant_id);

        // Fetched once; several checks read it. The error string is kept so each check reports it.
        let org = exo
            .one("Get-OrganizationConfig")
            .await
            .map_err(|e| e.to_string());
        let org_ref = || org.as_ref().map_err(|e| anyhow!("{e}"));

        // ── Authentication ──
        record_one(
            &mut findings,
            match org_ref() {
                Ok(o) => auth::check_modern_auth(graph, o, registry).await,
                Err(e) => Err(e),
            },
            "EXO-AUTH-001",
            CATEGORY,
            "Authentication",
            "Modern Authentication",
        );
        record_one(
            &mut findings,
            auth::check_smtp_auth(&exo, registry).await,
            "EXO-AUTH-002",
            CATEGORY,
            "Authentication",
            "SMTP AUTH Client Submission",
        );

        // ── Auditing ──
        record_one(
            &mut findings,
            audit::check_unified_audit_log(&exo, registry).await,
            "PURVIEW-AUDIT-001",
            "Compliance",
            "Audit & Logging",
            "Unified Audit Log",
        );
        record_one(
            &mut findings,
            org_ref().map(|o| audit::check_org_auditing(o, registry)),
            "EXO-AUDIT-001",
            CATEGORY,
            "Auditing",
            "Mailbox Auditing (organisation)",
        );
        record_one(
            &mut findings,
            audit::check_audit_bypass(&exo, registry).await,
            "EXO-AUDIT-002",
            CATEGORY,
            "Auditing",
            "Mailbox Audit Bypass",
        );
        record_one(
            &mut findings,
            audit::check_mailbox_audit_sets(&exo, registry).await,
            "EXO-AUDIT-003",
            CATEGORY,
            "Auditing",
            "Mailbox Audit Actions",
        );

        // ── Mail flow ──
        record_one(
            &mut findings,
            mailflow::check_forwarding(&exo, &tenant.verified_domains, registry).await,
            "EXO-FORWARD-001",
            CATEGORY,
            "Mail Flow",
            "Automatic Forwarding to External Recipients",
        );
        record_one(
            &mut findings,
            org_ref().map(|o| mailflow::check_direct_send(o, registry)),
            "EXO-DIRECTSEND-001",
            CATEGORY,
            "Mail Flow",
            "Reject Direct Send",
        );
        record_one(
            &mut findings,
            mailflow::check_transport_rules(&exo, registry).await,
            "EXO-TRANSPORT-001",
            CATEGORY,
            "Mail Flow",
            "Transport Rules Whitelisting",
        );
        match mailflow::check_connection_filter(&exo, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                let msg = e.to_string();
                record_one(
                    &mut findings,
                    Err(anyhow!("{msg}")),
                    "EXO-CONNFILTER-001",
                    CATEGORY,
                    "Mail Flow",
                    "Connection Filter IP Allow List",
                );
                record_one(
                    &mut findings,
                    Err(anyhow!("{msg}")),
                    "EXO-CONNFILTER-002",
                    CATEGORY,
                    "Mail Flow",
                    "Connection Filter Safe List",
                );
            }
        }
        record_one(
            &mut findings,
            mailflow::check_allowed_sender_domains(&exo, registry).await,
            "EXO-ANTISPAM-ALLOW-001",
            CATEGORY,
            "Mail Flow",
            "Anti-Spam Allowed Sender Domains",
        );
        record_one(
            &mut findings,
            mailflow::check_external_tagging(&exo, registry).await,
            "EXO-EXTTAG-001",
            CATEGORY,
            "Mail Flow",
            "External Sender Tagging",
        );
        record_one(
            &mut findings,
            org_ref().map(|o| mailflow::check_mailtips(o, registry)),
            "EXO-MAILTIPS-001",
            CATEGORY,
            "Mail Flow",
            "MailTips",
        );

        // ── Tenant and mailbox settings ──
        record_one(
            &mut findings,
            org_ref().map(|o| tenant::check_customer_lockbox(o, tenant, registry)),
            "EXO-LOCKBOX-001",
            CATEGORY,
            "Data Protection",
            "Customer Lockbox",
        );
        record_one(
            &mut findings,
            tenant::check_owa_storage_providers(&exo, registry).await,
            "EXO-OWA-001",
            CATEGORY,
            "Client Access",
            "Outlook on the web Storage Providers",
        );
        record_one(
            &mut findings,
            tenant::check_shared_mailbox_signin(&exo, graph, registry).await,
            "EXO-SHAREDMBX-001",
            CATEGORY,
            "Mailbox Security",
            "Shared Mailbox Sign-In",
        );
        record_one(
            &mut findings,
            tenant::check_calendar_sharing(&exo, registry).await,
            "EXO-SHARING-001",
            CATEGORY,
            "Sharing",
            "External Calendar Sharing",
        );
        record_one(
            &mut findings,
            tenant::check_user_addins(&exo, registry).await,
            "EXO-ADDINS-001",
            CATEGORY,
            "Client Access",
            "User Add-In Installation",
        );
        record_one(
            &mut findings,
            tenant::check_hidden_mailboxes(&exo, registry).await,
            "EXO-HIDDEN-001",
            CATEGORY,
            "Mailbox Security",
            "Mailboxes Hidden from Address Lists",
        );

        // ── Application access ──
        record_one(
            &mut findings,
            apps::check_app_mailbox_access(&exo, graph, registry).await,
            "EXO-APPRBAC-001",
            CATEGORY,
            "Application Access",
            "Application Mailbox Permissions Scoped",
        );

        // ── Email authentication per sending domain ──
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let dkim_configs = exo
            .get("Get-DkimSigningConfig", None)
            .await
            .map_err(|e| e.to_string());
        let mut assessed = 0usize;
        for domain in &tenant.verified_domains {
            if !dns::is_sending_domain(&resolver, domain).await {
                tracing::info!("{domain}: no MX or SPF record, skipped for SPF/DKIM/DMARC");
                continue;
            }
            assessed += 1;
            findings.extend(dns::check_domain(&resolver, domain, &dkim_configs, registry).await);
        }
        if assessed == 0 {
            let reason = anyhow!(
                "none of the {} verified domains has an MX or SPF record (Microsoft *.onmicrosoft.com domains are excluded)",
                tenant.verified_domains.len()
            );
            for (id, setting) in [
                ("DNS-SPF-001", "SPF Record"),
                ("DNS-DKIM-001", "DKIM Signing"),
                ("DNS-DMARC-001", "DMARC Policy"),
            ] {
                record(
                    &mut findings,
                    Err(anyhow!("{reason}")),
                    id,
                    CATEGORY,
                    "Email Authentication",
                    setting,
                );
            }
        }

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: serde_json::json!({
                "organization_config_available": org.is_ok(),
                "sending_domains_assessed": assessed,
            }),
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}
