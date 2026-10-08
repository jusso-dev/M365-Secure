//! Auditing: unified audit log ingestion, organisation mailbox auditing, per-mailbox audit sets
//! and audit bypass associations.

use anyhow::Result;
use serde_json::{json, Value};

use super::exo::{bool_of, bool_or, finding, list_preview, str_of, strs_of, Exo};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;

const CATEGORY: &str = "Exchange Online";
const SECTION: &str = "Auditing";

/// PURVIEW-AUDIT-001: unified audit log ingestion.
pub async fn check_unified_audit_log(exo: &Exo<'_>, registry: &ControlRegistry) -> Result<Finding> {
    let cfg = exo.one("Get-AdminAuditLogConfig").await?;
    let ingestion = bool_of(&cfg, "UnifiedAuditLogIngestionEnabled").ok_or_else(|| {
        anyhow::anyhow!("Get-AdminAuditLogConfig did not return UnifiedAuditLogIngestionEnabled")
    })?;
    Ok(finding(
        registry,
        "PURVIEW-AUDIT-001",
        "Compliance",
        "Audit & Logging",
        "Unified Audit Log",
        "Microsoft Purview unified audit logging is recording user and admin activity",
    )
    .status(if ingestion { FindingStatus::Pass } else { FindingStatus::Fail })
    .current_value(format!("UnifiedAuditLogIngestionEnabled = {}", ingestion))
    .expected_value("UnifiedAuditLogIngestionEnabled = True")
    .remediation(
        "Purview portal > Audit > Start recording user and admin activity, or run \
         Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true in Exchange Online PowerShell.",
    )
    .build())
}

/// EXO-AUDIT-001: organisation-level mailbox auditing.
pub fn check_org_auditing(org: &Value, registry: &ControlRegistry) -> Finding {
    let disabled = bool_or(org, "AuditDisabled", false);
    finding(
        registry,
        "EXO-AUDIT-001",
        CATEGORY,
        SECTION,
        "Mailbox Auditing (organisation)",
        "Mailbox auditing is on by default for all mailboxes (AuditDisabled = False)",
    )
    .status(if disabled {
        FindingStatus::Fail
    } else {
        FindingStatus::Pass
    })
    .current_value(format!(
        "Get-OrganizationConfig AuditDisabled = {}",
        disabled
    ))
    .expected_value("AuditDisabled = False")
    .remediation("Set-OrganizationConfig -AuditDisabled $false")
    .build()
}

/// Mailboxes whose audit configuration is weaker than the default set.
pub fn reduced_audit_mailboxes(mailboxes: &[Value]) -> Vec<String> {
    mailboxes
        .iter()
        .filter_map(|m| {
            let name = str_of(m, "PrimarySmtpAddress")
                .or_else(|| str_of(m, "Identity"))
                .unwrap_or("(unknown)");
            if !bool_or(m, "AuditEnabled", true) {
                return Some(format!("{} (AuditEnabled = False)", name));
            }
            let default_set = strs_of(m, "DefaultAuditSet");
            let missing: Vec<&str> = ["Admin", "Delegate", "Owner"]
                .into_iter()
                .filter(|k| !default_set.iter().any(|d| d.eq_ignore_ascii_case(k)))
                .collect();
            (!missing.is_empty())
                .then(|| format!("{} (custom audit set for {})", name, missing.join(", ")))
        })
        .collect()
}

/// EXO-AUDIT-003: per-mailbox audit actions have not been reduced below the default set.
pub async fn check_mailbox_audit_sets(
    exo: &Exo<'_>,
    registry: &ControlRegistry,
) -> Result<Finding> {
    const SAMPLE: usize = 500;
    let mailboxes = exo
        .get(
            "Get-Mailbox",
            Some(json!({
                "RecipientTypeDetails": ["UserMailbox", "SharedMailbox"],
                "ResultSize": SAMPLE
            })),
        )
        .await?;
    let reduced = reduced_audit_mailboxes(&mailboxes);
    let sampled_note = if mailboxes.len() >= SAMPLE {
        format!(" (first {} mailboxes checked)", SAMPLE)
    } else {
        String::new()
    };
    let mut f = finding(
        registry,
        "EXO-AUDIT-003",
        CATEGORY,
        SECTION,
        "Mailbox Audit Actions",
        "Every mailbox keeps the default audit action set for Admin, Delegate and Owner logons",
    )
    .status(if reduced.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    })
    .current_value(if reduced.is_empty() {
        format!(
            "{} mailbox(es) checked; all use AuditEnabled = True with the default audit set{}",
            mailboxes.len(),
            sampled_note
        )
    } else {
        format!(
            "{} of {} mailbox(es) have auditing off or a reduced audit set{}: {}",
            reduced.len(),
            mailboxes.len(),
            sampled_note,
            list_preview(&reduced, 10)
        )
    })
    .expected_value("AuditEnabled = True and DefaultAuditSet = Admin, Delegate, Owner on every mailbox")
    .remediation(
        "Set-Mailbox <mailbox> -AuditEnabled $true -DefaultAuditSet Admin,Delegate,Owner restores the Microsoft default \
         actions; use Set-Mailbox -AuditAdmin/-AuditDelegate/-AuditOwner only to add actions.",
    );
    if !reduced.is_empty() {
        f = f.affected_resources(reduced);
    }
    Ok(f.build())
}

/// Recipients with audit bypass enabled.
pub fn bypassed_recipients(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .filter(|r| bool_or(r, "AuditBypassEnabled", false))
        .map(|r| {
            str_of(r, "Identity")
                .or_else(|| str_of(r, "Name"))
                .unwrap_or("(unknown)")
                .to_string()
        })
        .collect()
}

/// EXO-AUDIT-002: no mailbox or account bypasses mailbox auditing.
pub async fn check_audit_bypass(exo: &Exo<'_>, registry: &ControlRegistry) -> Result<Finding> {
    let rows = exo
        .get(
            "Get-MailboxAuditBypassAssociation",
            Some(json!({"ResultSize": "Unlimited"})),
        )
        .await?;
    let bypassed = bypassed_recipients(&rows);
    let mut f = finding(
        registry,
        "EXO-AUDIT-002",
        CATEGORY,
        SECTION,
        "Mailbox Audit Bypass",
        "No mailbox or service account has AuditBypassEnabled, so every access is logged",
    )
    .status(if bypassed.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(if bypassed.is_empty() {
        format!("{} recipient(s) checked; none have AuditBypassEnabled", rows.len())
    } else {
        format!(
            "{} recipient(s) bypass mailbox auditing: {}",
            bypassed.len(),
            list_preview(&bypassed, 10)
        )
    })
    .expected_value("AuditBypassEnabled = False for every recipient")
    .remediation("Set-MailboxAuditBypassAssociation -Identity <account> -AuditBypassEnabled $false for each listed account.");
    if !bypassed.is_empty() {
        f = f.affected_resources(bypassed);
    }
    Ok(f.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduced_audit_sets_detected() {
        let mailboxes = vec![
            json!({"PrimarySmtpAddress": "ok@contoso.com", "AuditEnabled": true, "DefaultAuditSet": ["Admin", "Delegate", "Owner"]}),
            json!({"PrimarySmtpAddress": "off@contoso.com", "AuditEnabled": false, "DefaultAuditSet": ["Admin", "Delegate", "Owner"]}),
            json!({"PrimarySmtpAddress": "custom@contoso.com", "AuditEnabled": true, "DefaultAuditSet": ["Admin"]}),
        ];
        let reduced = reduced_audit_mailboxes(&mailboxes);
        assert_eq!(reduced.len(), 2);
        assert!(reduced[0].starts_with("off@"));
        assert!(reduced[1].contains("Delegate, Owner"));
    }

    #[test]
    fn bypass_rows_filtered() {
        let rows = vec![
            json!({"Identity": "svc-backup", "AuditBypassEnabled": true}),
            json!({"Identity": "user", "AuditBypassEnabled": false}),
        ];
        assert_eq!(bypassed_recipients(&rows), vec!["svc-backup"]);
    }
}
