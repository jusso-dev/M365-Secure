//! SharePoint and OneDrive checks (SPO-*), sourced from the CSOM tenant object with Graph
//! `sharepointSettings` as the fallback. Each check id tests what its registry name says; CIS refs in
//! comments are the v6 recommendation numbers the registry attaches.

use anyhow::Result;
use serde_json::Value;

use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::clients::spo::{
    self, DomainRestrictionMode, LinkPermission, LinkType, SharingCapability, TenantSharing,
};
use crate::graph::GraphClient;
use crate::modules::record_one;

const CATEGORY: &str = "Collaboration";

type Outcome = Result<(FindingStatus, String)>;

pub struct SpoData {
    pub sharing: TenantSharing,
    /// Why the CSOM read failed, when it did. Carries the consent hint from token acquisition.
    pub csom_error: Option<String>,
    pub graph_error: Option<String>,
    pub raw: Value,
}

impl SpoData {
    #[cfg(test)]
    pub fn from_sharing(sharing: TenantSharing) -> Self {
        Self {
            sharing,
            csom_error: None,
            graph_error: None,
            raw: Value::Null,
        }
    }

    /// A property neither source returned. The message says which API would have carried it.
    fn missing(&self, prop: &str) -> anyhow::Error {
        match (&self.csom_error, &self.graph_error) {
            (Some(e), None) => anyhow::anyhow!(
                "{prop} needs the SharePoint Online admin API, which did not answer: {e}"
            ),
            (Some(e), Some(g)) => anyhow::anyhow!(
                "{prop} needs the SharePoint Online admin API, which did not answer: {e} (Graph sharepointSettings also failed: {g})"
            ),
            (None, Some(g)) => anyhow::anyhow!(
                "SharePoint Online admin did not return {prop}, and Graph sharepointSettings failed: {g}"
            ),
            (None, None) => anyhow::anyhow!("SharePoint Online admin did not return {prop}"),
        }
    }

    fn need<T: Copy>(&self, v: Option<T>, prop: &str) -> Result<T> {
        v.ok_or_else(|| self.missing(prop))
    }

    fn sharing_disabled(&self) -> bool {
        self.sharing.sharing_capability == Some(SharingCapability::Disabled)
    }
}

pub async fn collect(graph: &GraphClient) -> SpoData {
    let csom = spo::fetch_tenant_properties(graph).await;
    let graph_settings = graph.get_json("/v1.0/admin/sharepoint/settings").await;
    if let Err(e) = &csom {
        tracing::warn!("SharePoint Online admin tenant properties unavailable: {e}");
    }
    let sharing = TenantSharing::merged(csom.as_ref().ok(), graph_settings.as_ref().ok());
    let raw = serde_json::json!({
        "csomTenant": csom.as_ref().ok(),
        "sharepointSettings": graph_settings.as_ref().ok(),
    });
    SpoData {
        sharing,
        csom_error: csom.err().map(|e| e.to_string()),
        graph_error: graph_settings.err().map(|e| e.to_string()),
        raw,
    }
}

struct Check {
    id: &'static str,
    section: &'static str,
    setting: &'static str,
    description: &'static str,
    expected: &'static str,
    remediation: &'static str,
}

fn emit(findings: &mut Vec<Finding>, registry: &ControlRegistry, c: &Check, outcome: Outcome) {
    let built = outcome.map(|(status, current)| {
        Finding::new(c.id, CATEGORY, c.section, c.setting, c.description)
            .status(status)
            .severity(registry.get_severity(c.id))
            .current_value(current)
            .expected_value(c.expected)
            .remediation(c.remediation)
            .build()
    });
    record_one(findings, built, c.id, CATEGORY, c.section, c.setting);
}

fn days(d: Option<i64>) -> String {
    match d {
        Some(n) if n > 0 => format!("{n} days"),
        Some(_) => "never".to_string(),
        None => "not returned".to_string(),
    }
}

fn perm(p: Option<LinkPermission>) -> &'static str {
    p.map(|p| p.label()).unwrap_or("not returned")
}

// SPO-SHARING-001 (7.2.3): organisation-level sharing is "New and existing guests" or stricter.
pub fn sharing_001(d: &SpoData) -> Outcome {
    let s = &d.sharing;
    let cap = d.need(s.sharing_capability, "SharingCapability")?;
    if !cap.allows_anyone_links() {
        return Ok((FindingStatus::Pass, cap.label().to_string()));
    }
    let expiring = s
        .anonymous_link_expire_in_days
        .is_some_and(|n| (1..=30).contains(&n));
    let view_only = s.file_anonymous_link_type == Some(LinkPermission::View)
        && s.folder_anonymous_link_type == Some(LinkPermission::View);
    let detail = format!(
        "Anyone links enabled (expiry: {}, file links: {}, folder links: {})",
        days(s.anonymous_link_expire_in_days),
        perm(s.file_anonymous_link_type),
        perm(s.folder_anonymous_link_type)
    );
    if expiring && view_only {
        Ok((
            FindingStatus::Warning,
            format!("{detail}; links are short-lived and view-only"),
        ))
    } else {
        Ok((FindingStatus::Fail, detail))
    }
}

// SPO-SHARING-009: Anyone links, where allowed, expire within 30 days and are view-only.
pub fn sharing_009(d: &SpoData) -> Outcome {
    let s = &d.sharing;
    let cap = d.need(s.sharing_capability, "SharingCapability")?;
    if !cap.allows_anyone_links() {
        return Ok((
            FindingStatus::Pass,
            "Anyone links disabled; expiry not applicable".to_string(),
        ));
    }
    let expiry = d.need(
        s.anonymous_link_expire_in_days,
        "RequireAnonymousLinksExpireInDays",
    )?;
    let file = d.need(s.file_anonymous_link_type, "FileAnonymousLinkType")?;
    let folder = d.need(s.folder_anonymous_link_type, "FolderAnonymousLinkType")?;
    let current = format!(
        "Expiry: {}, file links: {}, folder links: {}",
        days(Some(expiry)),
        file.label(),
        folder.label()
    );
    let expiring = (1..=30).contains(&expiry);
    let view_only = file == LinkPermission::View && folder == LinkPermission::View;
    Ok(match (expiring, view_only) {
        (true, true) => (FindingStatus::Pass, current),
        (true, false) => (
            FindingStatus::Warning,
            format!("{current}; Anyone links can edit"),
        ),
        (false, _) => (FindingStatus::Fail, current),
    })
}

// SPO-OD-001 (7.2.4): OneDrive sharing restricted.
pub fn od_001(d: &SpoData) -> Outcome {
    let cap = d.need(
        d.sharing.onedrive_sharing_capability,
        "OneDriveSharingCapability",
    )?;
    Ok(match cap {
        SharingCapability::Disabled => (FindingStatus::Pass, cap.label().to_string()),
        SharingCapability::ExternalUserAndGuestSharing => {
            (FindingStatus::Fail, cap.label().to_string())
        }
        _ => (
            FindingStatus::Warning,
            format!(
                "{}; CIS 7.2.4 recommends disabling OneDrive external sharing",
                cap.label()
            ),
        ),
    })
}

// SPO-SHARING-002 (7.2.5): guests cannot reshare items they don't own.
pub fn sharing_002(d: &SpoData) -> Outcome {
    if d.sharing_disabled() {
        return Ok((FindingStatus::Pass, "External sharing disabled".to_string()));
    }
    let prevent = d.need(
        d.sharing.prevent_external_resharing,
        "PreventExternalUsersFromResharing",
    )?;
    Ok(if prevent {
        (FindingStatus::Pass, "Guests cannot reshare".to_string())
    } else {
        (
            FindingStatus::Fail,
            "Guests can reshare items they don't own".to_string(),
        )
    })
}

// SPO-SHARING-003 (7.2.6): external sharing limited by a domain allow list.
pub fn sharing_003(d: &SpoData) -> Outcome {
    if d.sharing_disabled() {
        return Ok((FindingStatus::Pass, "External sharing disabled".to_string()));
    }
    let mode = d.need(
        d.sharing.domain_restriction_mode,
        "SharingDomainRestrictionMode",
    )?;
    Ok(match mode {
        DomainRestrictionMode::AllowList => (
            FindingStatus::Pass,
            format!(
                "Allow list with {} domain(s)",
                d.sharing.allowed_domains.len()
            ),
        ),
        DomainRestrictionMode::BlockList => (
            FindingStatus::Warning,
            "Block list only; an allow list is the restrictive option".to_string(),
        ),
        DomainRestrictionMode::None => (FindingStatus::Fail, "No domain restriction".to_string()),
    })
}

// SPO-SHARING-004 (7.2.7): default link type is "Specific people".
pub fn sharing_004(d: &SpoData) -> Outcome {
    let t = d.need(d.sharing.default_link_type, "DefaultSharingLinkType")?;
    Ok(match t {
        LinkType::Direct => (FindingStatus::Pass, t.label().to_string()),
        LinkType::AnonymousAccess => (FindingStatus::Fail, t.label().to_string()),
        LinkType::Internal | LinkType::None => (FindingStatus::Warning, t.label().to_string()),
    })
}

// SPO-SHARING-005 (7.2.9): guest access expires automatically (30 days or less).
pub fn sharing_005(d: &SpoData) -> Outcome {
    if d.sharing_disabled() {
        return Ok((FindingStatus::Pass, "External sharing disabled".to_string()));
    }
    let required = d.need(
        d.sharing.external_user_expiration_required,
        "ExternalUserExpirationRequired",
    )?;
    if !required {
        return Ok((
            FindingStatus::Fail,
            "Guest access does not expire".to_string(),
        ));
    }
    Ok(match d.sharing.external_user_expire_in_days {
        Some(n) if n <= 30 => (FindingStatus::Pass, format!("Expires after {n} days")),
        Some(n) => (
            FindingStatus::Warning,
            format!("Expires after {n} days (over 30)"),
        ),
        None => (
            FindingStatus::Warning,
            "Expiry required; period not returned".to_string(),
        ),
    })
}

// SPO-SHARING-006 (7.2.10): reauthentication with a verification code every 15 days or less.
pub fn sharing_006(d: &SpoData) -> Outcome {
    let required = d.need(
        d.sharing.email_attestation_required,
        "EmailAttestationRequired",
    )?;
    if !required {
        return Ok((
            FindingStatus::Fail,
            "Verification-code reauthentication not required".to_string(),
        ));
    }
    Ok(match d.sharing.email_attestation_reauth_days {
        Some(n) if n <= 15 => (FindingStatus::Pass, format!("Every {n} days")),
        Some(n) => (FindingStatus::Warning, format!("Every {n} days (over 15)")),
        None => (
            FindingStatus::Warning,
            "Required; interval not returned".to_string(),
        ),
    })
}

// SPO-SHARING-007 (7.2.11): default sharing link permission is View.
pub fn sharing_007(d: &SpoData) -> Outcome {
    let p = d.need(d.sharing.default_link_permission, "DefaultLinkPermission")?;
    Ok(match p {
        LinkPermission::View => (FindingStatus::Pass, p.label().to_string()),
        LinkPermission::Edit => (FindingStatus::Fail, p.label().to_string()),
        LinkPermission::None => (FindingStatus::Warning, p.label().to_string()),
    })
}

// SPO-SHARING-008 (7.2.8): external sharing limited to members of specific security groups.
pub fn sharing_008(d: &SpoData) -> Outcome {
    if d.sharing_disabled() {
        return Ok((FindingStatus::Pass, "External sharing disabled".to_string()));
    }
    match &d.sharing.who_can_share_allow_list {
        None => Err(anyhow::anyhow!(
            "WhoCanShareAllowListInTenant not returned; attest that 'Allow only users in specific security groups to share externally' is configured"
        )),
        Some(groups) if groups.is_empty() => {
            Ok((FindingStatus::Fail, "Any user can share externally".to_string()))
        }
        Some(groups) => Ok((FindingStatus::Pass, format!("{} security group(s) may share externally", groups.len()))),
    }
}

// SPO-AUTH-001 (7.2.1): legacy authentication protocols disabled.
pub fn auth_001(d: &SpoData) -> Outcome {
    let legacy = d.need(
        d.sharing.legacy_auth_protocols_enabled,
        "LegacyAuthProtocolsEnabled",
    )?;
    Ok(if legacy {
        (
            FindingStatus::Fail,
            "Legacy authentication protocols enabled".to_string(),
        )
    } else {
        (
            FindingStatus::Pass,
            "Modern authentication required".to_string(),
        )
    })
}

// SPO-B2B-001 (7.2.2): Entra B2B integration for SharePoint and OneDrive.
pub fn b2b_001(d: &SpoData) -> Outcome {
    if d.sharing_disabled() {
        return Ok((FindingStatus::Pass, "External sharing disabled".to_string()));
    }
    let b2b = d.need(
        d.sharing.b2b_integration_enabled,
        "EnableAzureADB2BIntegration",
    )?;
    Ok(if b2b {
        (FindingStatus::Pass, "Enabled".to_string())
    } else {
        (FindingStatus::Fail, "Disabled".to_string())
    })
}

// SPO-SYNC-001 (7.3.2): OneDrive sync restricted to managed devices.
pub fn sync_001(d: &SpoData) -> Outcome {
    let restricted = d.need(
        d.sharing.unmanaged_sync_restricted,
        "IsUnmanagedSyncClientForTenantRestricted",
    )?;
    Ok(if restricted {
        (
            FindingStatus::Pass,
            "Sync restricted to managed devices".to_string(),
        )
    } else {
        (
            FindingStatus::Fail,
            "Unmanaged devices can sync".to_string(),
        )
    })
}

// SPO-SYNC-002: Mac sync app enabled (posture note).
pub fn sync_002(d: &SpoData) -> Outcome {
    let enabled = d.need(d.sharing.mac_sync_app_enabled, "isMacSyncAppEnabled")?;
    Ok((
        FindingStatus::Info,
        if enabled { "Enabled" } else { "Disabled" }.to_string(),
    ))
}

// SPO-SCRIPT-001 (7.3.3) and SPO-SCRIPT-002 (7.3.4): custom script. SharePoint now blocks custom script
// on every site unless the tenant delays enforcement; per-site overrides are not visible tenant-wide.
pub fn script(d: &SpoData) -> Outcome {
    match d.sharing.delay_custom_script_enforcement {
        Some(false) => Ok((
            FindingStatus::Pass,
            "Custom script blocked by default; per-site overrides revert within 24 hours".to_string(),
        )),
        Some(true) => Ok((
            FindingStatus::Warning,
            "DelayDenyAddAndCustomizePagesEnforcement is on: custom script stays allowed where enabled".to_string(),
        )),
        None => Err(d.missing("DelayDenyAddAndCustomizePagesEnforcement")),
    }
}

// SPO-MALWARE-002 (7.3.1): infected files cannot be downloaded.
pub fn malware_002(d: &SpoData) -> Outcome {
    let disallow = d.need(
        d.sharing.disallow_infected_file_download,
        "DisallowInfectedFileDownload",
    )?;
    Ok(if disallow {
        (
            FindingStatus::Pass,
            "Infected file download blocked".to_string(),
        )
    } else {
        (
            FindingStatus::Fail,
            "Infected files can be downloaded".to_string(),
        )
    })
}

// SPO-LOOP-001: Loop components enabled (posture note).
pub fn loop_001(d: &SpoData) -> Outcome {
    let enabled = d.need(d.sharing.loop_enabled, "IsLoopEnabled")?;
    Ok((
        FindingStatus::Info,
        if enabled { "Enabled" } else { "Disabled" }.to_string(),
    ))
}

// SPO-LOOP-002: OneDrive Loop sharing no more permissive than guests.
pub fn loop_002(d: &SpoData) -> Outcome {
    let cap = d.need(
        d.sharing.onedrive_loop_sharing_capability,
        "OneDriveLoopSharingCapability",
    )?;
    Ok(if cap.allows_anyone_links() {
        (FindingStatus::Fail, cap.label().to_string())
    } else {
        (FindingStatus::Pass, cap.label().to_string())
    })
}

// SPO-SESSION-001 (1.3.2): idle session sign-out within 3 hours on unmanaged devices.
pub fn session_001(d: &SpoData) -> Outcome {
    let idle = d.need(d.sharing.idle_session_signout, "idleSessionSignOut")?;
    if !idle.is_enabled {
        return Ok((
            FindingStatus::Fail,
            "Idle session sign-out disabled".to_string(),
        ));
    }
    let hours = idle.sign_out_after_seconds as f64 / 3600.0;
    Ok(if idle.sign_out_after_seconds <= 3 * 3600 {
        (
            FindingStatus::Pass,
            format!("Sign out after {hours:.1} hours"),
        )
    } else {
        (
            FindingStatus::Warning,
            format!("Sign out after {hours:.1} hours (over 3)"),
        )
    })
}

/// SharePoint Advanced Management, standalone or through a Microsoft 365 Copilot licence.
pub fn has_advanced_management(tenant: &TenantInfo) -> bool {
    tenant.license_skus.iter().any(|sku| {
        let part = sku.sku_part_number.to_ascii_uppercase();
        part.contains("COPILOT")
            || part.contains("ADVANCED_MANAGEMENT")
            || sku.service_plans.iter().any(|p| {
                let p = p.to_ascii_uppercase();
                p.contains("ADVANCEDMANAGEMENT") || p.contains("ADVANCED_MANAGEMENT")
            })
    })
}

// SPO-RCD-001: restricted access control (and with it Restricted Content Discovery) available and on.
pub fn rcd_001(d: &SpoData, tenant: &TenantInfo) -> Outcome {
    match d.sharing.restricted_access_control_enabled {
        Some(true) => Ok((
            FindingStatus::Pass,
            "Restricted access control enabled for the tenant".to_string(),
        )),
        Some(false) if has_advanced_management(tenant) => Ok((
            FindingStatus::Warning,
            "Licensed for SharePoint Advanced Management but restricted access control is off"
                .to_string(),
        )),
        Some(false) => Ok((
            FindingStatus::NotLicensed,
            "Requires SharePoint Advanced Management (included with Microsoft 365 Copilot)"
                .to_string(),
        )),
        None => Err(d.missing("EnableRestrictedAccessControl")),
    }
}

pub fn evaluate(d: &SpoData, tenant: &TenantInfo, registry: &ControlRegistry) -> Vec<Finding> {
    let mut findings = Vec::new();
    let sharing = "SharePoint Sharing";
    let access = "SharePoint Access Control";

    let checks: Vec<(Check, Outcome)> = vec![
        (
            Check {
                id: "SPO-SHARING-001",
                section: sharing,
                setting: "External sharing level",
                description: "Organisation-level sharing is 'New and existing guests' or more restrictive, so Anyone links are off",
                expected: "New and existing guests, existing guests only, or only people in your organization",
                remediation: "Lower the SharePoint organisation-level sharing setting below 'Anyone' in the SharePoint admin center > Policies > Sharing.",
            },
            sharing_001(d),
        ),
        (
            Check {
                id: "SPO-SHARING-009",
                section: sharing,
                setting: "Anyone link expiry and permission",
                description: "Where Anyone links are allowed they expire within 30 days and grant view only",
                expected: "Anyone links disabled, or expiry of 30 days or less with view-only file and folder links",
                remediation: "Under 'Choose expiration and permissions options for Anyone links', set expiry to 30 days or less and both file and folder links to View.",
            },
            sharing_009(d),
        ),
        (
            Check {
                id: "SPO-OD-001",
                section: "OneDrive",
                setting: "OneDrive external sharing",
                description: "OneDrive content sharing is restricted",
                expected: "Only people in your organization",
                remediation: "Set the OneDrive slider to 'Only people in your organization' (it cannot be more permissive than SharePoint).",
            },
            od_001(d),
        ),
        (
            Check {
                id: "SPO-SHARING-002",
                section: sharing,
                setting: "Guest resharing",
                description: "Guests cannot share items they don't own",
                expected: "Allow guests to share items they don't own: off",
                remediation: "Clear 'Allow guests to share items they don't own' under More external sharing settings.",
            },
            sharing_002(d),
        ),
        (
            Check {
                id: "SPO-SHARING-003",
                section: sharing,
                setting: "Domain restriction",
                description: "External sharing is limited to an allow list of domains",
                expected: "Limit external sharing by domain: allow list",
                remediation: "Enable 'Limit external sharing by domain' and allow only approved partner domains.",
            },
            sharing_003(d),
        ),
        (
            Check {
                id: "SPO-SHARING-004",
                section: sharing,
                setting: "Default sharing link type",
                description: "Link sharing defaults to 'Specific people'",
                expected: "Specific people (only the people the user specifies)",
                remediation: "Set 'Choose the type of link that is selected by default' to Specific people.",
            },
            sharing_004(d),
        ),
        (
            Check {
                id: "SPO-SHARING-005",
                section: sharing,
                setting: "Guest access expiration",
                description: "Guest access to a site or OneDrive expires automatically",
                expected: "Guest access expires after 30 days or less",
                remediation: "Enable 'Guest access to a site or OneDrive will expire automatically after this many days' and set 30 or less.",
            },
            sharing_005(d),
        ),
        (
            Check {
                id: "SPO-SHARING-006",
                section: sharing,
                setting: "Verification code reauthentication",
                description: "Guests using a verification code must reauthenticate every 15 days or less",
                expected: "People who use a verification code must reauthenticate after 15 days or less",
                remediation: "Enable 'People who use a verification code must reauthenticate after this many days' and set 15 or less.",
            },
            sharing_006(d),
        ),
        (
            Check {
                id: "SPO-SHARING-007",
                section: sharing,
                setting: "Default sharing link permission",
                description: "The default sharing link permission is View",
                expected: "View",
                remediation: "Set 'Choose the permission that is selected by default for sharing links' to View.",
            },
            sharing_007(d),
        ),
        (
            Check {
                id: "SPO-SHARING-008",
                section: sharing,
                setting: "Security group restriction",
                description: "Only members of specific security groups can share externally",
                expected: "Allow only users in specific security groups to share externally: configured",
                remediation: "Under More external sharing settings, enable 'Allow only users in specific security groups to share externally' and pick the groups.",
            },
            sharing_008(d),
        ),
        (
            Check {
                id: "SPO-AUTH-001",
                section: access,
                setting: "Legacy authentication",
                description: "Modern authentication is required for SharePoint applications",
                expected: "Apps that don't use modern authentication: blocked",
                remediation: "Set 'Apps that don't use modern authentication' to Block under Policies > Access control.",
            },
            auth_001(d),
        ),
        (
            Check {
                id: "SPO-B2B-001",
                section: sharing,
                setting: "Entra B2B integration",
                description: "SharePoint and OneDrive guest access uses Entra B2B",
                expected: "EnableAzureADB2BIntegration: true",
                remediation: "Run Set-SPOTenant -EnableAzureADB2BIntegration $true so guests are governed by Entra external collaboration settings.",
            },
            b2b_001(d),
        ),
        (
            Check {
                id: "SPO-SYNC-001",
                section: access,
                setting: "Unmanaged device sync",
                description: "OneDrive sync is restricted to managed devices",
                expected: "Allow syncing only on computers joined to specific domains",
                remediation: "Under Settings > OneDrive sync, allow syncing only on devices joined to specific domains, or block sync from unmanaged devices.",
            },
            sync_001(d),
        ),
        (
            Check {
                id: "SPO-SYNC-002",
                section: access,
                setting: "Mac sync app",
                description: "Whether the OneDrive sync app is allowed on macOS",
                expected: "Informational",
                remediation: "Review whether macOS sync is needed; if so, cover macOS with Intune compliance and the unmanaged-device sync restriction.",
            },
            sync_002(d),
        ),
        (
            Check {
                id: "SPO-SCRIPT-001",
                section: access,
                setting: "Custom script on personal sites",
                description: "Custom script execution is blocked on personal (OneDrive) sites",
                expected: "Custom script blocked",
                remediation: "Keep DelayDenyAddAndCustomizePagesEnforcement off and do not re-enable custom script on OneDrive sites.",
            },
            script(d),
        ),
        (
            Check {
                id: "SPO-SCRIPT-002",
                section: access,
                setting: "Custom script on site collections",
                description: "Custom script execution is blocked on site collections",
                expected: "Custom script blocked",
                remediation: "Keep DelayDenyAddAndCustomizePagesEnforcement off; where a site has DenyAddAndCustomizePages disabled, re-enable it.",
            },
            script(d),
        ),
        (
            Check {
                id: "SPO-MALWARE-002",
                section: access,
                setting: "Infected file download",
                description: "Files SharePoint detects as infected cannot be downloaded",
                expected: "DisallowInfectedFileDownload: true",
                remediation: "Run Set-SPOTenant -DisallowInfectedFileDownload $true.",
            },
            malware_002(d),
        ),
        (
            Check {
                id: "SPO-LOOP-001",
                section: sharing,
                setting: "Loop components",
                description: "Whether Loop components are enabled",
                expected: "Informational",
                remediation: "If Loop is enabled, make sure OneDrive Loop sharing is no more permissive than SharePoint sharing.",
            },
            loop_001(d),
        ),
        (
            Check {
                id: "SPO-LOOP-002",
                section: sharing,
                setting: "OneDrive Loop sharing",
                description: "OneDrive Loop sharing does not allow Anyone links",
                expected: "OneDriveLoopSharingCapability no more permissive than New and existing guests",
                remediation: "Run Set-SPOTenant -OneDriveLoopSharingCapability ExternalUserSharingOnly (or Disabled).",
            },
            loop_002(d),
        ),
        (
            Check {
                id: "SPO-SESSION-001",
                section: access,
                setting: "Idle session sign-out",
                description: "Idle browser sessions on unmanaged devices sign out within 3 hours",
                expected: "Idle session sign-out enabled, 3 hours or less",
                remediation: "Under Policies > Access control > Idle session sign-out, enable it with a sign-out time of 3 hours or less.",
            },
            session_001(d),
        ),
        (
            Check {
                id: "SPO-RCD-001",
                section: "SharePoint Governance",
                setting: "Restricted access control",
                description: "SharePoint Advanced Management restricted access control is enabled so crown-jewel sites can be limited to a group and hidden from Copilot and search",
                expected: "EnableRestrictedAccessControl: true",
                remediation: "With SharePoint Advanced Management, run Set-SPOTenant -EnableRestrictedAccessControl $true, then apply Set-SPOSite -RestrictedAccessControl and -RestrictContentOrgWideSearch to sensitive sites.",
            },
            rcd_001(d, tenant),
        ),
    ];
    for (check, outcome) in checks {
        emit(&mut findings, registry, &check, outcome);
    }

    // SPO-DAG-001: data access governance reports have no REST surface; the control is attestation-only.
    findings.push(
        Finding::new(
            "SPO-DAG-001",
            CATEGORY,
            "SharePoint Governance",
            "Data access governance reports",
            "Oversharing (data access governance) reports are run at least quarterly and findings tracked to closure",
        )
        .status(FindingStatus::Unknown)
        .severity(registry.get_severity("SPO-DAG-001"))
        .current_value(
            "Not automatable: Get-SPODataAccessGovernanceInsight has no REST path. Attest that a DAG report ran in the last 90 days.",
        )
        .expected_value("A data access governance report generated in the last 90 days")
        .remediation(
            "In the SharePoint admin center > Reports > Data access governance, run the sharing links and 'Everyone except external users' reports quarterly and follow up with site access reviews.",
        )
        .build(),
    );

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::engine::LicenseSku;
    use crate::clients::spo::IdleSessionSignOut;

    fn tight() -> SpoData {
        SpoData::from_sharing(TenantSharing {
            sharing_capability: Some(SharingCapability::ExternalUserSharingOnly),
            onedrive_sharing_capability: Some(SharingCapability::Disabled),
            default_link_type: Some(LinkType::Direct),
            default_link_permission: Some(LinkPermission::View),
            anonymous_link_expire_in_days: Some(0),
            file_anonymous_link_type: Some(LinkPermission::View),
            folder_anonymous_link_type: Some(LinkPermission::View),
            domain_restriction_mode: Some(DomainRestrictionMode::AllowList),
            allowed_domains: vec!["contoso.com".into()],
            prevent_external_resharing: Some(true),
            external_user_expiration_required: Some(true),
            external_user_expire_in_days: Some(30),
            email_attestation_required: Some(true),
            email_attestation_reauth_days: Some(15),
            legacy_auth_protocols_enabled: Some(false),
            restricted_access_control_enabled: Some(true),
            who_can_share_allow_list: Some(vec!["g1".into()]),
            b2b_integration_enabled: Some(true),
            unmanaged_sync_restricted: Some(true),
            disallow_infected_file_download: Some(true),
            delay_custom_script_enforcement: Some(false),
            loop_enabled: Some(true),
            onedrive_loop_sharing_capability: Some(SharingCapability::ExternalUserSharingOnly),
            idle_session_signout: Some(IdleSessionSignOut {
                is_enabled: true,
                sign_out_after_seconds: 7200,
            }),
            mac_sync_app_enabled: Some(true),
        })
    }

    fn tenant(sku: &str) -> TenantInfo {
        TenantInfo {
            tenant_id: "t".into(),
            display_name: "T".into(),
            verified_domains: vec!["contoso.onmicrosoft.com".into()],
            primary_domain: "contoso.com".into(),
            license_skus: vec![LicenseSku {
                sku_id: "s".into(),
                sku_part_number: sku.into(),
                consumed_units: 1,
                prepaid_units: 1,
                service_plans: vec![],
            }],
        }
    }

    #[test]
    fn tight_tenant_passes_everything_automatable() {
        let d = tight();
        let reg = ControlRegistry::load(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("controls")
                .as_path(),
        )
        .unwrap();
        let findings = evaluate(&d, &tenant("SPE_E5"), &reg);
        let non_pass: Vec<_> = findings
            .iter()
            .filter(|f| !matches!(f.status, FindingStatus::Pass | FindingStatus::Info))
            .map(|f| f.check_id.as_str())
            .collect();
        assert_eq!(non_pass, vec!["SPO-DAG-001"], "{non_pass:?}");
        assert_eq!(findings.len(), 22);
    }

    #[test]
    fn anyone_links_fail_unless_short_lived_and_view_only() {
        let mut d = tight();
        d.sharing.sharing_capability = Some(SharingCapability::ExternalUserAndGuestSharing);
        assert_eq!(sharing_001(&d).unwrap().0, FindingStatus::Fail);
        assert_eq!(sharing_009(&d).unwrap().0, FindingStatus::Fail);
        d.sharing.anonymous_link_expire_in_days = Some(14);
        assert_eq!(sharing_001(&d).unwrap().0, FindingStatus::Warning);
        assert_eq!(sharing_009(&d).unwrap().0, FindingStatus::Pass);
        d.sharing.file_anonymous_link_type = Some(LinkPermission::Edit);
        assert_eq!(sharing_001(&d).unwrap().0, FindingStatus::Fail);
        assert_eq!(sharing_009(&d).unwrap().0, FindingStatus::Warning);
    }

    #[test]
    fn missing_csom_property_is_unknown_with_consent_reason() {
        let mut d = SpoData::from_sharing(TenantSharing {
            sharing_capability: Some(SharingCapability::ExternalUserSharingOnly),
            ..Default::default()
        });
        d.csom_error = Some(
            "SharePoint Online admin token acquisition failed: AADSTS65001 ... consented".into(),
        );
        let err = sharing_004(&d).unwrap_err().to_string();
        assert!(
            err.contains("DefaultSharingLinkType") && err.contains("consented"),
            "{err}"
        );

        let reg = ControlRegistry::load(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("controls")
                .as_path(),
        )
        .unwrap();
        let findings = evaluate(&d, &tenant("SPE_E3"), &reg);
        let f = findings
            .iter()
            .find(|f| f.check_id == "SPO-SHARING-007")
            .unwrap();
        assert_eq!(f.status, FindingStatus::Unknown);
        assert!(
            f.current_value.contains("Grant the permission"),
            "{}",
            f.current_value
        );
        // Sharing level came from Graph, so it still evaluates.
        let f = findings
            .iter()
            .find(|f| f.check_id == "SPO-SHARING-001")
            .unwrap();
        assert_eq!(f.status, FindingStatus::Pass);
    }

    #[test]
    fn restricted_access_control_depends_on_licence() {
        let mut d = tight();
        d.sharing.restricted_access_control_enabled = Some(false);
        assert_eq!(
            rcd_001(&d, &tenant("SPE_E3")).unwrap().0,
            FindingStatus::NotLicensed
        );
        assert_eq!(
            rcd_001(&d, &tenant("Microsoft_365_Copilot")).unwrap().0,
            FindingStatus::Warning
        );
        assert!(has_advanced_management(&tenant(
            "SharePoint_Advanced_Management"
        )));
    }

    #[test]
    fn disabled_sharing_short_circuits_dependent_checks() {
        let d = SpoData::from_sharing(TenantSharing {
            sharing_capability: Some(SharingCapability::Disabled),
            ..Default::default()
        });
        for f in [sharing_002, sharing_003, sharing_005, sharing_008, b2b_001] {
            assert_eq!(f(&d).unwrap().0, FindingStatus::Pass);
        }
        assert!(sharing_007(&d).is_err());
    }

    #[test]
    fn thresholds() {
        let mut d = tight();
        d.sharing.external_user_expire_in_days = Some(60);
        assert_eq!(sharing_005(&d).unwrap().0, FindingStatus::Warning);
        d.sharing.email_attestation_reauth_days = Some(30);
        assert_eq!(sharing_006(&d).unwrap().0, FindingStatus::Warning);
        d.sharing.idle_session_signout = Some(IdleSessionSignOut {
            is_enabled: true,
            sign_out_after_seconds: 4 * 3600,
        });
        assert_eq!(session_001(&d).unwrap().0, FindingStatus::Warning);
        d.sharing.domain_restriction_mode = Some(DomainRestrictionMode::None);
        assert_eq!(sharing_003(&d).unwrap().0, FindingStatus::Fail);
        d.sharing.who_can_share_allow_list = Some(vec![]);
        assert_eq!(sharing_008(&d).unwrap().0, FindingStatus::Fail);
        d.sharing.who_can_share_allow_list = None;
        assert!(sharing_008(&d).is_err());
        d.sharing.onedrive_sharing_capability = Some(SharingCapability::ExternalUserSharingOnly);
        assert_eq!(od_001(&d).unwrap().0, FindingStatus::Warning);
    }
}
