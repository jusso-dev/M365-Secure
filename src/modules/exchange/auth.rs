//! Authentication controls: modern authentication (OAuth) and SMTP AUTH client submission.

use anyhow::Result;
use serde_json::{json, Value};

use super::exo::{bool_of, finding, list_preview, str_of, Exo};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

const CATEGORY: &str = "Exchange Online";
const SECTION: &str = "Authentication";

/// Name of an enabled Conditional Access policy that blocks legacy authentication clients for all users.
pub fn legacy_auth_block_policy(policies: &[Value]) -> Option<String> {
    policies.iter().find_map(|p| {
        let enabled = str_of(p, "state") == Some("enabled");
        let apps = p
            .pointer("/conditions/clientAppTypes")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let legacy = apps.contains(&"exchangeActiveSync") && apps.contains(&"other");
        let blocks = p
            .pointer("/grantControls/builtInControls")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|c| c.as_str() == Some("block")));
        let all_users = p
            .pointer("/conditions/users/includeUsers")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|u| u.as_str() == Some("All")));
        (enabled && legacy && blocks && all_users)
            .then(|| str_of(p, "displayName").unwrap_or("(unnamed)").to_string())
    })
}

/// EXO-AUTH-001: OAuth2ClientProfileEnabled plus the tenant's legacy-authentication block.
pub async fn check_modern_auth(
    graph: &GraphClient,
    org: &Value,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let oauth = bool_of(org, "OAuth2ClientProfileEnabled").ok_or_else(|| {
        anyhow::anyhow!("Get-OrganizationConfig did not return OAuth2ClientProfileEnabled")
    })?;

    let security_defaults = graph
        .get_json("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy")
        .await
        .ok()
        .and_then(|p| bool_of(&p, "isEnabled"));
    let ca_policies: Option<Vec<Value>> = graph
        .get_all::<Value>("/v1.0/identity/conditionalAccess/policies")
        .await
        .ok();
    let ca_block = ca_policies.as_deref().and_then(legacy_auth_block_policy);

    let legacy_state = match (security_defaults, &ca_block) {
        (Some(true), _) => Some("legacy authentication blocked by Security Defaults".to_string()),
        (_, Some(name)) => Some(format!(
            "legacy authentication blocked by Conditional Access policy '{}'",
            name
        )),
        _ => None,
    };
    let evidence_available = security_defaults.is_some() || ca_policies.is_some();

    let (status, current) = match (oauth, &legacy_state) {
        (false, _) => (
            FindingStatus::Fail,
            "OAuth2ClientProfileEnabled = False; Outlook clients fall back to basic authentication".to_string(),
        ),
        (true, Some(block)) => (FindingStatus::Pass, format!("OAuth2ClientProfileEnabled = True; {}", block)),
        (true, None) if evidence_available => (
            FindingStatus::Warning,
            "OAuth2ClientProfileEnabled = True, but neither Security Defaults nor an all-users Conditional Access policy \
             blocks legacy authentication clients"
                .to_string(),
        ),
        (true, None) => (
            FindingStatus::Warning,
            "OAuth2ClientProfileEnabled = True; the Security Defaults and Conditional Access state could not be read \
             (Policy.Read.All), so the legacy-authentication block is unverified"
                .to_string(),
        ),
    };

    Ok(finding(
        registry,
        "EXO-AUTH-001",
        CATEGORY,
        SECTION,
        "Modern Authentication",
        "Exchange Online requires modern (OAuth) authentication and legacy authentication is blocked",
    )
    .status(status)
    .current_value(current)
    .expected_value("OAuth2ClientProfileEnabled = True and legacy authentication blocked tenant-wide")
    .remediation(
        "Set-OrganizationConfig -OAuth2ClientProfileEnabled $true, then block legacy clients with Security Defaults or a \
         Conditional Access policy (Entra admin center > Protection > Conditional Access) targeting Exchange ActiveSync \
         clients and Other clients with Block access for all users.",
    )
    .build())
}

/// EXO-AUTH-002: SMTP AUTH disabled at the organisation, with per-mailbox exceptions listed.
pub async fn check_smtp_auth(exo: &Exo<'_>, registry: &ControlRegistry) -> Result<Finding> {
    let transport = exo.one("Get-TransportConfig").await?;
    let disabled = bool_of(&transport, "SmtpClientAuthenticationDisabled").ok_or_else(|| {
        anyhow::anyhow!("Get-TransportConfig did not return SmtpClientAuthenticationDisabled")
    })?;

    let exceptions = exo
        .get(
            "Get-CASMailbox",
            Some(json!({
                "Filter": "SmtpClientAuthenticationDisabled -eq $false",
                "ResultSize": 21
            })),
        )
        .await;

    let (status, current, affected) = match (disabled, exceptions) {
        (false, _) => (
            FindingStatus::Fail,
            "SmtpClientAuthenticationDisabled = False; SMTP AUTH (basic authentication) is accepted for every mailbox".to_string(),
            vec![],
        ),
        (true, Ok(mailboxes)) if mailboxes.is_empty() => (
            FindingStatus::Pass,
            "SmtpClientAuthenticationDisabled = True and no mailbox re-enables SMTP AUTH".to_string(),
            vec![],
        ),
        (true, Ok(mailboxes)) => {
            let names: Vec<String> = mailboxes
                .iter()
                .map(|m| {
                    str_of(m, "PrimarySmtpAddress")
                        .or_else(|| str_of(m, "Identity"))
                        .or_else(|| str_of(m, "Name"))
                        .unwrap_or("(unknown)")
                        .to_string()
                })
                .collect();
            let count_text = if names.len() > 20 {
                "more than 20".to_string()
            } else {
                names.len().to_string()
            };
            (
                FindingStatus::Warning,
                format!(
                    "SmtpClientAuthenticationDisabled = True at the organisation, but {} mailbox(es) re-enable SMTP AUTH: {}",
                    count_text,
                    list_preview(&names, 20)
                ),
                names,
            )
        }
        (true, Err(e)) => (
            FindingStatus::Warning,
            format!(
                "SmtpClientAuthenticationDisabled = True at the organisation; per-mailbox exceptions could not be enumerated ({})",
                e
            ),
            vec![],
        ),
    };

    let mut f = finding(
        registry,
        "EXO-AUTH-002",
        CATEGORY,
        SECTION,
        "SMTP AUTH Client Submission",
        "SMTP AUTH is disabled for the organisation and enabled only on named mailboxes that need it",
    )
    .status(status)
    .current_value(current)
    .expected_value("Set-TransportConfig SmtpClientAuthenticationDisabled = True; no or documented per-mailbox exceptions")
    .remediation(
        "Set-TransportConfig -SmtpClientAuthenticationDisabled $true. For devices that still need it, run \
         Set-CASMailbox <mailbox> -SmtpClientAuthenticationDisabled $false on that mailbox only and move it to OAuth, \
         Microsoft Graph or a connector relay when possible.",
    );
    if !affected.is_empty() {
        f = f.affected_resources(affected);
    }
    Ok(f.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_all_users_legacy_block_policy() {
        let policies = vec![
            json!({"displayName": "Report only", "state": "enabledForReportingButNotEnforced",
                   "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"], "users": {"includeUsers": ["All"]}},
                   "grantControls": {"builtInControls": ["block"]}}),
            json!({"displayName": "Block legacy", "state": "enabled",
                   "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"], "users": {"includeUsers": ["All"]}},
                   "grantControls": {"builtInControls": ["block"]}}),
        ];
        assert_eq!(
            legacy_auth_block_policy(&policies).as_deref(),
            Some("Block legacy")
        );
        assert!(legacy_auth_block_policy(&policies[..1]).is_none());
    }
}
