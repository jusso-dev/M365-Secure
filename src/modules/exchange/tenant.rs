//! Tenant and mailbox settings: Customer Lockbox, Outlook on the web storage providers, shared
//! mailbox sign-in, calendar sharing, user add-ins and hidden mailboxes.

use anyhow::Result;
use serde_json::{json, Value};

use super::exo::{bool_or, finding, list_preview, name_of, str_of, strs_of, Exo};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

const CATEGORY: &str = "Exchange Online";

/// EXO-LOCKBOX-001
pub fn check_customer_lockbox(
    org: &Value,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Finding {
    let f = finding(
        registry,
        "EXO-LOCKBOX-001",
        CATEGORY,
        "Data Protection",
        "Customer Lockbox",
        "Microsoft support engineers need explicit approval before accessing tenant data",
    )
    .expected_value("CustomerLockBoxEnabled = True")
    .remediation(
        "Microsoft 365 admin center > Settings > Org settings > Security & privacy > Customer Lockbox > Require approval, \
         or Set-OrganizationConfig -CustomerLockBoxEnabled $true.",
    );
    if !(tenant.has_service_plan("LOCKBOX_ENTERPRISE") || tenant.has_e5()) {
        return f
            .status(FindingStatus::NotLicensed)
            .current_value("No Customer Lockbox service plan (LOCKBOX_ENTERPRISE / E5) detected")
            .build();
    }
    let enabled = bool_or(org, "CustomerLockBoxEnabled", false);
    f.status(if enabled {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(format!("CustomerLockBoxEnabled = {}", enabled))
    .build()
}

/// EXO-OWA-001
pub async fn check_owa_storage_providers(
    exo: &Exo<'_>,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policies = exo.get("Get-OwaMailboxPolicy", None).await?;
    let offending: Vec<String> = policies
        .iter()
        .filter(|p| bool_or(p, "AdditionalStorageProvidersAvailable", true))
        .map(name_of)
        .collect();
    let mut f = finding(
        registry,
        "EXO-OWA-001",
        CATEGORY,
        "Client Access",
        "Outlook on the web Storage Providers",
        "Outlook on the web cannot attach files from third-party storage providers (Dropbox, Google Drive, Box)",
    )
    .status(if offending.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(if offending.is_empty() {
        format!(
            "{} OWA mailbox policy(ies); AdditionalStorageProvidersAvailable = False on all",
            policies.len()
        )
    } else {
        format!(
            "AdditionalStorageProvidersAvailable = True on: {}",
            list_preview(&offending, 10)
        )
    })
    .expected_value("AdditionalStorageProvidersAvailable = False on every OWA mailbox policy")
    .remediation("Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -AdditionalStorageProvidersAvailable $false (repeat per policy).");
    if !offending.is_empty() {
        f = f.affected_resources(offending);
    }
    Ok(f.build())
}

/// EXO-SHAREDMBX-001: shared mailboxes with sign-in still enabled.
pub async fn check_shared_mailbox_signin(
    exo: &Exo<'_>,
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let shared = exo
        .get(
            "Get-Mailbox",
            Some(json!({"RecipientTypeDetails": "SharedMailbox", "ResultSize": 1000})),
        )
        .await?;
    let ids: Vec<(String, String)> = shared
        .iter()
        .filter_map(|m| {
            let id = str_of(m, "ExternalDirectoryObjectId")?;
            let name = str_of(m, "PrimarySmtpAddress")
                .or_else(|| str_of(m, "Identity"))
                .unwrap_or(id);
            Some((id.to_string(), name.to_string()))
        })
        .collect();

    let mut enabled: Vec<String> = Vec::new();
    for chunk in ids.chunks(15) {
        let filter = chunk
            .iter()
            .map(|(id, _)| format!("'{}'", id))
            .collect::<Vec<_>>()
            .join(",");
        let users: Vec<Value> = graph
            .get_all::<Value>(&format!(
                "/v1.0/users?$select=id,accountEnabled,userPrincipalName&$filter=id in ({})",
                filter
            ))
            .await?;
        for u in users.iter().filter(|u| bool_or(u, "accountEnabled", false)) {
            let id = str_of(u, "id").unwrap_or("");
            let label = chunk
                .iter()
                .find(|(cid, _)| cid == id)
                .map(|(_, n)| n.clone())
                .or_else(|| str_of(u, "userPrincipalName").map(String::from))
                .unwrap_or_else(|| id.to_string());
            enabled.push(label);
        }
    }

    let mut f = finding(
        registry,
        "EXO-SHAREDMBX-001",
        CATEGORY,
        "Mailbox Security",
        "Shared Mailbox Sign-In",
        "Shared mailboxes cannot be signed into directly; access is only through delegated users",
    )
    .status(if enabled.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(if enabled.is_empty() {
        format!("{} shared mailbox(es); sign-in blocked on all", ids.len())
    } else {
        format!(
            "{} of {} shared mailbox(es) have accountEnabled = True: {}",
            enabled.len(),
            ids.len(),
            list_preview(&enabled, 10)
        )
    })
    .expected_value("accountEnabled = False for every shared mailbox account")
    .remediation(
        "Microsoft 365 admin center > Users > Active users > select the shared mailbox account > Block sign-in, or \
         Update-MgUser -UserId <id> -AccountEnabled:$false.",
    );
    if !enabled.is_empty() {
        f = f.affected_resources(enabled);
    }
    Ok(f.build())
}

/// Sharing-policy domain entries that expose calendars externally. Returns (policy, entry) pairs
/// split into anonymous/any-domain grants and named-domain grants.
pub fn external_calendar_grants(policies: &[Value]) -> (Vec<String>, Vec<String>) {
    let mut broad = Vec::new();
    let mut named = Vec::new();
    for p in policies.iter().filter(|p| bool_or(p, "Enabled", true)) {
        for entry in strs_of(p, "Domains") {
            let Some((domain, action)) = entry.split_once(':') else {
                continue;
            };
            if !action.to_ascii_lowercase().contains("calendarsharing") {
                continue;
            }
            let text = format!("{}: {}", name_of(p), entry);
            if domain == "*" || domain.eq_ignore_ascii_case("Anonymous") {
                broad.push(text);
            } else {
                named.push(text);
            }
        }
    }
    (broad, named)
}

/// EXO-SHARING-001
pub async fn check_calendar_sharing(exo: &Exo<'_>, registry: &ControlRegistry) -> Result<Finding> {
    let policies = exo.get("Get-SharingPolicy", None).await?;
    let (broad, named) = external_calendar_grants(&policies);
    let status = if !broad.is_empty() {
        FindingStatus::Fail
    } else if !named.is_empty() {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    let mut affected = broad.clone();
    affected.extend(named.iter().cloned());
    let mut f = finding(
        registry,
        "EXO-SHARING-001",
        CATEGORY,
        "Sharing",
        "External Calendar Sharing",
        "Calendars cannot be shared with anonymous users or every external domain",
    )
    .status(status)
    .current_value(if affected.is_empty() {
        format!("{} enabled sharing policy(ies); no external calendar sharing grants", policies.len())
    } else {
        format!(
            "{} anonymous/any-domain grant(s), {} named-domain grant(s): {}",
            broad.len(),
            named.len(),
            list_preview(&affected, 6)
        )
    })
    .expected_value("No enabled sharing policy grants CalendarSharing* to Anonymous or *")
    .remediation(
        "Microsoft 365 admin center > Settings > Org settings > Calendar: turn off external sharing, or \
         Set-SharingPolicy -Identity 'Default Sharing Policy' -Enabled $false (or remove the Anonymous/* domain entries).",
    );
    if !affected.is_empty() {
        f = f.affected_resources(affected);
    }
    Ok(f.build())
}

/// EXO-ADDINS-001
pub async fn check_user_addins(exo: &Exo<'_>, registry: &ControlRegistry) -> Result<Finding> {
    let policies = exo.get("Get-RoleAssignmentPolicy", None).await?;
    const APP_ROLES: [&str; 3] = [
        "My Custom Apps",
        "My Marketplace Apps",
        "My ReadWriteMailbox Apps",
    ];
    let offending: Vec<String> = policies
        .iter()
        .filter(|p| bool_or(p, "IsDefault", false))
        .flat_map(|p| {
            let name = name_of(p);
            strs_of(p, "AssignedRoles")
                .into_iter()
                .filter(|r| APP_ROLES.iter().any(|a| r.eq_ignore_ascii_case(a)))
                .map(move |r| format!("{}: {}", name, r))
        })
        .collect();
    let mut f = finding(
        registry,
        "EXO-ADDINS-001",
        CATEGORY,
        "Client Access",
        "User Add-In Installation",
        "Users cannot install their own Outlook add-ins",
    )
    .status(if offending.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    })
    .current_value(if offending.is_empty() {
        "Default role assignment policy does not grant My Custom Apps, My Marketplace Apps or My ReadWriteMailbox Apps"
            .to_string()
    } else {
        format!("Default role assignment policy grants: {}", offending.join(", "))
    })
    .expected_value("My Custom Apps, My Marketplace Apps and My ReadWriteMailbox Apps removed from the default policy")
    .remediation(
        "Exchange admin center > Roles > User roles > Default Role Assignment Policy: untick the three app roles, or \
         Set-RoleAssignmentPolicy -Identity 'Default Role Assignment Policy' -Roles @{Remove='My Custom Apps','My Marketplace Apps','My ReadWriteMailbox Apps'}.",
    );
    if !offending.is_empty() {
        f = f.affected_resources(offending);
    }
    Ok(f.build())
}

/// EXO-HIDDEN-001
pub async fn check_hidden_mailboxes(exo: &Exo<'_>, registry: &ControlRegistry) -> Result<Finding> {
    let hidden = exo
        .get(
            "Get-Mailbox",
            Some(json!({
                "RecipientTypeDetails": "UserMailbox",
                "Filter": "HiddenFromAddressListsEnabled -eq $true",
                "ResultSize": 100
            })),
        )
        .await?;
    let names: Vec<String> = hidden
        .iter()
        .map(|m| {
            str_of(m, "PrimarySmtpAddress")
                .or_else(|| str_of(m, "Identity"))
                .unwrap_or("(unknown)")
                .to_string()
        })
        .collect();
    let mut f = finding(
        registry,
        "EXO-HIDDEN-001",
        CATEGORY,
        "Mailbox Security",
        "Mailboxes Hidden from Address Lists",
        "No user mailbox is hidden from the Global Address List, a common attacker persistence trick",
    )
    .status(if names.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    })
    .current_value(if names.is_empty() {
        "No user mailbox has HiddenFromAddressListsEnabled = True".to_string()
    } else {
        format!(
            "{}{} user mailbox(es) hidden from the GAL: {}",
            if names.len() >= 100 { "at least " } else { "" },
            names.len(),
            list_preview(&names, 10)
        )
    })
    .expected_value("HiddenFromAddressListsEnabled = False on user mailboxes unless documented")
    .remediation(
        "Review each listed mailbox; for legitimate users run Set-Mailbox <mailbox> -HiddenFromAddressListsEnabled $false, \
         and investigate unexpected entries as possible compromise.",
    );
    if !names.is_empty() {
        f = f.affected_resources(names);
    }
    Ok(f.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_grants_split_broad_and_named() {
        let policies = vec![
            json!({"Name": "Default Sharing Policy", "Enabled": true,
                   "Domains": ["Anonymous:CalendarSharingFreeBusySimple", "partner.example:CalendarSharingFreeBusyDetail", "*:ContactsSharing"]}),
            json!({"Name": "Disabled", "Enabled": false, "Domains": ["*:CalendarSharingFreeBusyReviewer"]}),
        ];
        let (broad, named) = external_calendar_grants(&policies);
        assert_eq!(broad.len(), 1);
        assert_eq!(named.len(), 1);
    }
}
