//! Mail flow controls: forwarding, Direct Send, transport rules, connection filtering, allowed
//! sender domains, external tagging and MailTips.

use anyhow::Result;
use serde_json::Value;

use super::exo::{
    bool_of, bool_or, finding, i64_of, list_preview, name_of, rule_enabled, str_of, strs_of, Exo,
};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;

const CATEGORY: &str = "Exchange Online";
const SECTION: &str = "Mail Flow";

// ─── EXO-FORWARD-001 ─────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub struct ForwardEval {
    pub status: FindingStatus,
    pub summary: String,
    pub affected: Vec<String>,
}

fn is_external(address: &str, internal_domains: &[String]) -> bool {
    match address.rsplit_once('@') {
        Some((_, domain)) => !internal_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain)),
        None => false,
    }
}

/// Transport rules (enabled) that redirect, bcc or add external recipients.
pub fn external_forwarding_rules(
    transport_rules: &[Value],
    internal_domains: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    for rule in transport_rules.iter().filter(|r| rule_enabled(r)) {
        let mut targets: Vec<String> = Vec::new();
        for key in [
            "RedirectMessageTo",
            "BlindCopyTo",
            "AddToRecipients",
            "CopyTo",
        ] {
            targets.extend(
                strs_of(rule, key)
                    .into_iter()
                    .filter(|a| is_external(a, internal_domains)),
            );
        }
        if !targets.is_empty() {
            out.push(format!("{} -> {}", name_of(rule), targets.join(", ")));
        }
    }
    out
}

/// Evaluate outbound-spam forwarding policies plus transport rules. `rules` are the
/// `Get-HostedOutboundSpamFilterRule` rows when available, used to show the scope of non-default policies.
pub fn evaluate_forwarding(
    policies: &[Value],
    rules: Option<&[Value]>,
    transport_rules: &[Value],
    remote_domains: &[Value],
    internal_domains: &[String],
) -> ForwardEval {
    let default = policies
        .iter()
        .find(|p| bool_or(p, "IsDefault", false) || name_of(p).eq_ignore_ascii_case("Default"));
    let Some(default) = default else {
        return ForwardEval {
            status: FindingStatus::Fail,
            summary: "Get-HostedOutboundSpamFilterPolicy returned no default policy".to_string(),
            affected: vec![],
        };
    };
    let default_mode = str_of(default, "AutoForwardingMode").unwrap_or("Automatic");
    let mut status = if default_mode.eq_ignore_ascii_case("On") {
        FindingStatus::Fail
    } else {
        FindingStatus::Pass
    };
    let mut parts = vec![format!(
        "Default outbound spam policy AutoForwardingMode = {}{}",
        default_mode,
        if default_mode.eq_ignore_ascii_case("Automatic") {
            " (system-controlled, blocks forwarding)"
        } else {
            ""
        }
    )];
    let mut affected = Vec::new();

    for policy in policies.iter().filter(|p| !std::ptr::eq(*p, default)) {
        if !str_of(policy, "AutoForwardingMode").is_some_and(|m| m.eq_ignore_ascii_case("On")) {
            continue;
        }
        let name = name_of(policy);
        let scope = rules.and_then(|rs| {
            rs.iter()
                .find(|r| str_of(r, "HostedOutboundSpamFilterPolicy").is_some_and(|p| p == name))
        });
        let (scoped, scope_text) = match scope {
            Some(rule) => {
                let users = strs_of(rule, "From");
                let groups = strs_of(rule, "FromMemberOf");
                let domains = strs_of(rule, "SenderDomainIs");
                let named = !users.is_empty() || !groups.is_empty();
                let text = format!(
                    "{} user(s), {} group(s), {} sender domain(s){}",
                    users.len(),
                    groups.len(),
                    domains.len(),
                    if rule_enabled(rule) {
                        ""
                    } else {
                        ", rule disabled"
                    }
                );
                (named || !rule_enabled(rule), text)
            }
            None => (false, "scope could not be read".to_string()),
        };
        if scoped {
            if status == FindingStatus::Pass {
                status = FindingStatus::Warning;
            }
            parts.push(format!(
                "exception policy '{}' allows forwarding for {}",
                name, scope_text
            ));
        } else {
            status = FindingStatus::Fail;
            parts.push(format!(
                "policy '{}' allows forwarding and is not limited to named users or groups ({})",
                name, scope_text
            ));
        }
        affected.push(name);
    }

    let rule_hits = external_forwarding_rules(transport_rules, internal_domains);
    if !rule_hits.is_empty() {
        status = FindingStatus::Fail;
        parts.push(format!(
            "{} mail flow rule(s) forward to external addresses: {}",
            rule_hits.len(),
            list_preview(&rule_hits, 5)
        ));
        affected.extend(rule_hits);
    }

    if let Some(remote_default) = remote_domains.iter().find(|d| {
        str_of(d, "DomainName") == Some("*") || name_of(d).eq_ignore_ascii_case("Default")
    }) {
        parts.push(format!(
            "remote domain Default AutoForwardEnabled = {} (supporting detail; the outbound spam policy is the effective control)",
            bool_or(remote_default, "AutoForwardEnabled", true)
        ));
    }

    ForwardEval {
        status,
        summary: parts.join("; "),
        affected,
    }
}

pub async fn check_forwarding(
    exo: &Exo<'_>,
    internal_domains: &[String],
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policies = exo.get("Get-HostedOutboundSpamFilterPolicy", None).await?;
    let rules = exo.get("Get-HostedOutboundSpamFilterRule", None).await.ok();
    let transport_rules = exo.get("Get-TransportRule", None).await.unwrap_or_default();
    let remote_domains = exo.get("Get-RemoteDomain", None).await.unwrap_or_default();
    let eval = evaluate_forwarding(
        &policies,
        rules.as_deref(),
        &transport_rules,
        &remote_domains,
        internal_domains,
    );
    let mut f = finding(
        registry,
        "EXO-FORWARD-001",
        CATEGORY,
        SECTION,
        "Automatic Forwarding to External Recipients",
        "Automatic forwarding is blocked by the outbound spam policy, exceptions are scoped to named mailboxes, and no mail flow rule forwards externally",
    )
    .status(eval.status)
    .current_value(eval.summary)
    .expected_value("Default policy AutoForwardingMode Off or Automatic; exception policies scoped to named users; no transport rule redirects externally")
    .remediation(
        "Defender portal > Email & collaboration > Policies & rules > Threat policies > Anti-spam > Anti-spam outbound policy (Default): \
         set Automatic forwarding rules to Off (Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off). \
         Put approved exceptions in a separate policy whose rule targets named users or a group, and remove mail flow rules \
         that redirect or Bcc to external addresses.",
    );
    if !eval.affected.is_empty() {
        f = f.affected_resources(eval.affected);
    }
    Ok(f.build())
}

// ─── EXO-DIRECTSEND-001 ──────────────────────────────────────────────────────

pub fn check_direct_send(org: &Value, registry: &ControlRegistry) -> Finding {
    let (status, current) = match bool_of(org, "RejectDirectSend") {
        Some(true) => (FindingStatus::Pass, "RejectDirectSend = True".to_string()),
        Some(false) => (
            FindingStatus::Fail,
            "RejectDirectSend = False; unauthenticated mail claiming an accepted domain is accepted via Direct Send".to_string(),
        ),
        None => (
            FindingStatus::Unknown,
            "Get-OrganizationConfig did not return RejectDirectSend; the setting may not be available to this tenant yet".to_string(),
        ),
    };
    finding(
        registry,
        "EXO-DIRECTSEND-001",
        CATEGORY,
        SECTION,
        "Reject Direct Send",
        "Direct Send is rejected so devices and attackers cannot deliver unauthenticated mail as an internal sender",
    )
    .status(status)
    .current_value(current)
    .expected_value("RejectDirectSend = True")
    .remediation(
        "Run Set-OrganizationConfig -RejectDirectSend $true after moving multifunction devices and applications to \
         SMTP AUTH client submission (OAuth), Microsoft Graph or an inbound connector.",
    )
    .build()
}

// ─── EXO-TRANSPORT-001 ───────────────────────────────────────────────────────

/// Enabled transport rules that bypass filtering: SCL -1 (whitelisting) or authentication header rewrites.
pub fn evaluate_transport_rules(rules: &[Value]) -> (FindingStatus, Vec<String>, Vec<String>) {
    let mut fails = Vec::new();
    let mut warnings = Vec::new();
    for rule in rules.iter().filter(|r| rule_enabled(r)) {
        let name = name_of(rule);
        if i64_of(rule, "SetSCL") == Some(-1) {
            let domains = strs_of(rule, "SenderDomainIs");
            if domains.is_empty() {
                fails.push(format!("{}: sets SCL -1 (bypasses spam filtering)", name));
            } else {
                fails.push(format!(
                    "{}: sets SCL -1 for sender domain(s) {}",
                    name,
                    list_preview(&domains, 5)
                ));
            }
        }
        if str_of(rule, "SetHeaderName").is_some_and(|h| {
            h.to_ascii_lowercase()
                .contains("x-ms-exchange-organization-authas")
        }) {
            warnings.push(format!("{}: rewrites the AuthAs header", name));
        }
    }
    let status = if !fails.is_empty() {
        FindingStatus::Fail
    } else if !warnings.is_empty() {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    (status, fails, warnings)
}

pub async fn check_transport_rules(exo: &Exo<'_>, registry: &ControlRegistry) -> Result<Finding> {
    let rules = exo.get("Get-TransportRule", None).await?;
    let (status, fails, warnings) = evaluate_transport_rules(&rules);
    let enabled = rules.iter().filter(|r| rule_enabled(r)).count();
    let mut issues = fails.clone();
    issues.extend(warnings);
    let current = if issues.is_empty() {
        format!(
            "{} enabled mail flow rule(s); none whitelist senders or bypass filtering",
            enabled
        )
    } else {
        format!(
            "{} enabled mail flow rule(s); {}",
            enabled,
            issues.join("; ")
        )
    };
    let mut f = finding(
        registry,
        "EXO-TRANSPORT-001",
        CATEGORY,
        SECTION,
        "Transport Rules Whitelisting",
        "No mail flow rule sets SCL -1 for sender domains or otherwise bypasses spam filtering",
    )
    .status(status)
    .current_value(current)
    .expected_value("No enabled rule with SetSCL -1 or AuthAs header rewrites")
    .remediation(
        "Exchange admin center > Mail flow > Rules: remove or disable rules that set the spam confidence level to -1 \
         (Bypass spam filtering). Use Tenant Allow/Block List or anti-spam policy allowed senders only when unavoidable.",
    );
    if !issues.is_empty() {
        f = f.affected_resources(issues);
    }
    Ok(f.build())
}

// ─── EXO-CONNFILTER-001 / 002 ────────────────────────────────────────────────

pub async fn check_connection_filter(
    exo: &Exo<'_>,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let policies = exo.get("Get-HostedConnectionFilterPolicy", None).await?;
    let allow: Vec<String> = policies
        .iter()
        .flat_map(|p| strs_of(p, "IPAllowList"))
        .collect();
    let safe_list_on: Vec<String> = policies
        .iter()
        .filter(|p| bool_or(p, "EnableSafeList", false))
        .map(name_of)
        .collect();

    let mut allow_finding = finding(
        registry,
        "EXO-CONNFILTER-001",
        CATEGORY,
        SECTION,
        "Connection Filter IP Allow List",
        "The connection filter IP allow list is not used",
    )
    .status(if allow.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(if allow.is_empty() {
        "IPAllowList is empty".to_string()
    } else {
        format!(
            "{} IP range(s) bypass spam filtering: {}",
            allow.len(),
            list_preview(&allow, 10)
        )
    })
    .expected_value("IPAllowList empty")
    .remediation(
        "Defender portal > Policies & rules > Threat policies > Anti-spam > Connection filter policy (Default): clear \
         Always allow messages from the following IP addresses (Set-HostedConnectionFilterPolicy -Identity Default -IPAllowList @{}).",
    );
    if !allow.is_empty() {
        allow_finding = allow_finding.affected_resources(allow);
    }

    let safe_finding = finding(
        registry,
        "EXO-CONNFILTER-002",
        CATEGORY,
        SECTION,
        "Connection Filter Safe List",
        "The connection filter safe list (Microsoft-curated trusted senders) is off",
    )
    .status(if safe_list_on.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(if safe_list_on.is_empty() {
        "EnableSafeList = False".to_string()
    } else {
        format!("EnableSafeList = True on: {}", safe_list_on.join(", "))
    })
    .expected_value("EnableSafeList = False")
    .remediation(
        "Set-HostedConnectionFilterPolicy -Identity Default -EnableSafeList $false, or clear Turn on safe list in the \
         connection filter policy.",
    )
    .build();

    Ok(vec![allow_finding.build(), safe_finding])
}

// ─── EXO-ANTISPAM-ALLOW-001 ──────────────────────────────────────────────────

/// Policy -> allowed sender domains, for policies that have any.
pub fn allowed_sender_domains(policies: &[Value]) -> Vec<(String, Vec<String>)> {
    policies
        .iter()
        .filter_map(|p| {
            let domains = strs_of(p, "AllowedSenderDomains");
            (!domains.is_empty()).then(|| (name_of(p), domains))
        })
        .collect()
}

pub async fn check_allowed_sender_domains(
    exo: &Exo<'_>,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policies = exo.get("Get-HostedContentFilterPolicy", None).await?;
    let hits = allowed_sender_domains(&policies);
    let affected: Vec<String> = hits
        .iter()
        .map(|(p, d)| format!("{}: {}", p, d.join(", ")))
        .collect();
    let mut f = finding(
        registry,
        "EXO-ANTISPAM-ALLOW-001",
        CATEGORY,
        SECTION,
        "Anti-Spam Allowed Sender Domains",
        "No inbound anti-spam policy allow-lists whole sender domains",
    )
    .status(if hits.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(if hits.is_empty() {
        format!("{} anti-spam policy(ies); AllowedSenderDomains empty on all", policies.len())
    } else {
        format!(
            "{} policy(ies) allow-list domains, bypassing spam and most phishing checks: {}",
            hits.len(),
            list_preview(&affected, 5)
        )
    })
    .expected_value("AllowedSenderDomains empty on every anti-spam policy")
    .remediation(
        "Defender portal > Policies & rules > Threat policies > Anti-spam > each inbound policy > Allowed and blocked \
         senders and domains: remove allowed domains (Set-HostedContentFilterPolicy -Identity <name> -AllowedSenderDomains @{}). \
         Use the Tenant Allow/Block List or partner connectors for specific trusted senders.",
    );
    if !affected.is_empty() {
        f = f.affected_resources(affected);
    }
    Ok(f.build())
}

// ─── EXO-EXTTAG-001 ──────────────────────────────────────────────────────────

pub async fn check_external_tagging(exo: &Exo<'_>, registry: &ControlRegistry) -> Result<Finding> {
    let rows = exo.get("Get-ExternalInOutlook", None).await?;
    let enabled = rows.iter().any(|r| bool_or(r, "Enabled", false));
    let allow: Vec<String> = rows.iter().flat_map(|r| strs_of(r, "AllowList")).collect();
    Ok(finding(
        registry,
        "EXO-EXTTAG-001",
        CATEGORY,
        SECTION,
        "External Sender Tagging",
        "Mail from outside the organisation is tagged External in Outlook",
    )
    .status(if enabled {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(if enabled {
        format!(
            "ExternalInOutlook Enabled = True{}",
            if allow.is_empty() {
                String::new()
            } else {
                format!(
                    "; {} sender(s)/domain(s) exempt: {}",
                    allow.len(),
                    list_preview(&allow, 5)
                )
            }
        )
    } else {
        "ExternalInOutlook Enabled = False".to_string()
    })
    .expected_value("Enabled = True")
    .remediation("Run Set-ExternalInOutlook -Enabled $true in Exchange Online PowerShell.")
    .build())
}

// ─── EXO-MAILTIPS-001 ────────────────────────────────────────────────────────

pub fn check_mailtips(org: &Value, registry: &ControlRegistry) -> Finding {
    let all = bool_or(org, "MailTipsAllTipsEnabled", false);
    let external = bool_or(org, "MailTipsExternalRecipientsTipsEnabled", false);
    let metrics = bool_or(org, "MailTipsGroupMetricsEnabled", false);
    let threshold = i64_of(org, "MailTipsLargeAudienceThreshold").unwrap_or(25);
    let ok = all && external && metrics && threshold <= 25;
    finding(
        registry,
        "EXO-MAILTIPS-001",
        CATEGORY,
        SECTION,
        "MailTips",
        "MailTips warn users about external recipients and large audiences",
    )
    .status(if ok { FindingStatus::Pass } else { FindingStatus::Fail })
    .current_value(format!(
        "MailTipsAllTipsEnabled={} MailTipsExternalRecipientsTipsEnabled={} MailTipsGroupMetricsEnabled={} MailTipsLargeAudienceThreshold={}",
        all, external, metrics, threshold
    ))
    .expected_value("All four MailTips settings on, large audience threshold <= 25")
    .remediation(
        "Set-OrganizationConfig -MailTipsAllTipsEnabled $true -MailTipsExternalRecipientsTipsEnabled $true \
         -MailTipsGroupMetricsEnabled $true -MailTipsLargeAudienceThreshold 25",
    )
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn domains() -> Vec<String> {
        vec!["contoso.com".into(), "contoso.onmicrosoft.com".into()]
    }

    #[test]
    fn forwarding_passes_on_automatic_default_without_exceptions() {
        let policies =
            vec![json!({"Name": "Default", "IsDefault": true, "AutoForwardingMode": "Automatic"})];
        let eval = evaluate_forwarding(&policies, None, &[], &[], &domains());
        assert_eq!(eval.status, FindingStatus::Pass);
        assert!(eval.affected.is_empty());
    }

    #[test]
    fn forwarding_fails_when_default_is_on() {
        let policies =
            vec![json!({"Name": "Default", "IsDefault": true, "AutoForwardingMode": "On"})];
        assert_eq!(
            evaluate_forwarding(&policies, None, &[], &[], &domains()).status,
            FindingStatus::Fail
        );
    }

    #[test]
    fn forwarding_scoped_exception_is_warning_and_unscoped_is_fail() {
        let policies = vec![
            json!({"Name": "Default", "IsDefault": true, "AutoForwardingMode": "Off"}),
            json!({"Name": "Finance exceptions", "IsDefault": false, "AutoForwardingMode": "On"}),
        ];
        let rules = vec![json!({
            "Name": "Finance exceptions",
            "HostedOutboundSpamFilterPolicy": "Finance exceptions",
            "State": "Enabled",
            "From": ["cfo@contoso.com"]
        })];
        let eval = evaluate_forwarding(&policies, Some(&rules), &[], &[], &domains());
        assert_eq!(eval.status, FindingStatus::Warning);
        assert_eq!(eval.affected, vec!["Finance exceptions"]);

        let broad = vec![json!({
            "Name": "Finance exceptions",
            "HostedOutboundSpamFilterPolicy": "Finance exceptions",
            "State": "Enabled",
            "SenderDomainIs": ["contoso.com"]
        })];
        assert_eq!(
            evaluate_forwarding(&policies, Some(&broad), &[], &[], &domains()).status,
            FindingStatus::Fail
        );
    }

    #[test]
    fn transport_rule_external_redirect_fails() {
        let policies =
            vec![json!({"Name": "Default", "IsDefault": true, "AutoForwardingMode": "Off"})];
        let rules = vec![
            json!({"Name": "Archive", "State": "Enabled", "BlindCopyTo": ["archive@contoso.com"]}),
            json!({"Name": "Leak", "State": "Enabled", "RedirectMessageTo": ["x@evil.example"]}),
            json!({"Name": "Old leak", "State": "Disabled", "RedirectMessageTo": ["y@evil.example"]}),
        ];
        let eval = evaluate_forwarding(&policies, None, &rules, &[], &domains());
        assert_eq!(eval.status, FindingStatus::Fail);
        assert_eq!(eval.affected.len(), 1);
        assert!(eval.affected[0].starts_with("Leak"));
    }

    #[test]
    fn transport_rules_scl_minus_one_fails() {
        let rules = vec![
            json!({"Name": "Partner", "State": "Enabled", "SetSCL": -1, "SenderDomainIs": ["partner.example"]}),
            json!({"Name": "Hdr", "State": "Enabled", "SetHeaderName": "X-MS-Exchange-Organization-AuthAs"}),
            json!({"Name": "Off", "State": "Disabled", "SetSCL": -1}),
        ];
        let (status, fails, warns) = evaluate_transport_rules(&rules);
        assert_eq!(status, FindingStatus::Fail);
        assert_eq!(fails.len(), 1);
        assert_eq!(warns.len(), 1);
        assert_eq!(evaluate_transport_rules(&[]).0, FindingStatus::Pass);
    }

    #[test]
    fn allowed_domains_collected_per_policy() {
        let policies = vec![
            json!({"Name": "Default", "AllowedSenderDomains": []}),
            json!({"Name": "Custom", "AllowedSenderDomains": ["partner.example", {"Domain": "other.example"}]}),
        ];
        let hits = allowed_sender_domains(&policies);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, vec!["partner.example", "other.example"]);
    }
}
