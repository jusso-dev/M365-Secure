use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct CollaborationModule;

#[async_trait]
impl AssessmentModule for CollaborationModule {
    fn name(&self) -> &str {
        "Collaboration"
    }

    fn description(&self) -> &str {
        "SharePoint, Teams, and Forms collaboration assessment module"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        _tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();
        let mut raw_data = serde_json::json!({});

        // --- SharePoint Settings ---
        let spo_settings = graph.get_json("/v1.0/admin/sharepoint/settings").await;
        if let Ok(ref spo) = spo_settings {
            raw_data["sharepointSettings"] = spo.clone();
        }

        // SPO-SHARING-001: External sharing level
        match &spo_settings {
            Ok(spo) => {
                let sharing_capability = spo
                    .get("sharingCapability")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let (status, current): (FindingStatus, String) = match sharing_capability {
                    "disabled" | "existingExternalUserSharingOnly" | "externalUserSharingOnly" => {
                        (FindingStatus::Pass, sharing_capability.to_string())
                    }
                    "externalUserAndGuestSharing" => {
                        (FindingStatus::Fail, sharing_capability.to_string())
                    }
                    other => (FindingStatus::Review, other.to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SHARING-001",
                        "Collaboration",
                        "SharePoint Sharing",
                        "External Sharing Level",
                        "Evaluate the external sharing level for SharePoint Online",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SHARING-001"))
                    .current_value(current)
                    .expected_value("ExternalUserSharingOnly or more restrictive".to_string())
                    .remediation("Set SharePoint external sharing to 'Existing guests only' or more restrictive in SharePoint admin center > Policies > Sharing".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SHARING-001",
                        "Collaboration",
                        "SharePoint Sharing",
                        "External Sharing Level",
                        "Evaluate the external sharing level for SharePoint Online",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SHARING-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("ExternalUserSharingOnly or more restrictive".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SHARING-002: Default sharing link type
        match &spo_settings {
            Ok(spo) => {
                let link_type = spo
                    .get("defaultSharingLinkType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let (status, current): (FindingStatus, String) = match link_type {
                    "specificPeople" => (FindingStatus::Pass, link_type.to_string()),
                    "none" => (FindingStatus::Review, "Not configured".to_string()),
                    other => (FindingStatus::Fail, other.to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SHARING-002",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Default Sharing Link Type",
                        "Check that the default sharing link type is set to Specific People",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SHARING-002"))
                    .current_value(current)
                    .expected_value("SpecificPeople".to_string())
                    .remediation("Set default sharing link type to 'Specific people' in SharePoint admin center > Policies > Sharing".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SHARING-002",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Default Sharing Link Type",
                        "Check that the default sharing link type is set to Specific People",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SHARING-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("SpecificPeople".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SHARING-003: Default sharing link permission
        match &spo_settings {
            Ok(spo) => {
                let link_perm = spo
                    .get("defaultLinkPermission")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let (status, current): (FindingStatus, String) = match link_perm {
                    "view" => (FindingStatus::Pass, link_perm.to_string()),
                    other => (FindingStatus::Fail, other.to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SHARING-003",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Default Sharing Link Permission",
                        "Check that the default sharing link permission is set to View",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SHARING-003"))
                    .current_value(current)
                    .expected_value("View".to_string())
                    .remediation("Set default sharing link permission to 'View' in SharePoint admin center > Policies > Sharing".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SHARING-003",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Default Sharing Link Permission",
                        "Check that the default sharing link permission is set to View",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SHARING-003"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("View".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SHARING-004: Resharing by external users
        match &spo_settings {
            Ok(spo) => {
                let resharing = spo
                    .get("isResharingByExternalUsersEnabled")
                    .and_then(|v| v.as_bool());

                let (status, current): (FindingStatus, String) = match resharing {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Fail, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Not configured".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SHARING-004",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Resharing by External Users",
                        "Check that external users cannot reshare content they do not own",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SHARING-004"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Disable resharing by external users in SharePoint admin center > Policies > Sharing > More external sharing settings".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SHARING-004",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Resharing by External Users",
                        "Check that external users cannot reshare content they do not own",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SHARING-004"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SHARING-005: Guest access expiration
        match &spo_settings {
            Ok(spo) => {
                let expiration_days = spo
                    .get("externalUserExpirationInDays")
                    .and_then(|v| v.as_i64());
                let expiration_required = spo
                    .get("externalUserExpireInDays")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        // Some tenants use isGuestAccessExpirationRequired
                        spo.get("isGuestAccessExpirationRequired")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) =
                    match (expiration_required, expiration_days) {
                        (Some(true), Some(days)) if days > 0 && days <= 90 => {
                            (FindingStatus::Pass, format!("Enabled, {} days", days))
                        }
                        (Some(true), Some(days)) if days > 90 => (
                            FindingStatus::Warning,
                            format!("Enabled, {} days (>90)", days),
                        ),
                        (Some(true), _) => (FindingStatus::Pass, "Enabled".to_string()),
                        (Some(false), _) => (FindingStatus::Fail, "Disabled".to_string()),
                        (None, Some(days)) if days > 0 => {
                            (FindingStatus::Pass, format!("{} days", days))
                        }
                        _ => (FindingStatus::Review, "Not configured".to_string()),
                    };

                findings.push(
                    Finding::new(
                        "SPO-SHARING-005",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Guest Access Expiration",
                        "Check that guest access links expire within an appropriate timeframe",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SHARING-005"))
                    .current_value(current)
                    .expected_value("Enabled with expiration <= 90 days".to_string())
                    .remediation("Enable guest access expiration and set to 90 days or less in SharePoint admin center > Policies > Sharing".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SHARING-005",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Guest Access Expiration",
                        "Check that guest access links expire within an appropriate timeframe",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SHARING-005"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Enabled with expiration <= 90 days".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SHARING-006: Sharing domain restrictions
        match &spo_settings {
            Ok(spo) => {
                let domain_restriction_mode = spo
                    .get("sharingDomainRestrictionMode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("none");

                let (status, current): (FindingStatus, String) = match domain_restriction_mode {
                    "allowList" => (FindingStatus::Pass, "Allow list configured".to_string()),
                    "blockList" => (FindingStatus::Warning, "Block list configured".to_string()),
                    "none" => (FindingStatus::Fail, "No domain restrictions".to_string()),
                    other => (FindingStatus::Review, other.to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SHARING-006",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Sharing Domain Restrictions",
                        "Check that sharing domain restrictions are configured to limit external sharing",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SHARING-006"))
                    .current_value(current)
                    .expected_value("Allow list or block list configured".to_string())
                    .remediation("Configure sharing domain restrictions in SharePoint admin center > Policies > Sharing > Advanced settings".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SHARING-006",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Sharing Domain Restrictions",
                        "Check that sharing domain restrictions are configured to limit external sharing",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SHARING-006"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Allow list or block list configured".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-AUTH-001: Legacy auth protocols disabled
        match &spo_settings {
            Ok(spo) => {
                let legacy_auth = spo
                    .get("isLegacyAuthProtocolsEnabled")
                    .and_then(|v| v.as_bool());

                let (status, current): (FindingStatus, String) = match legacy_auth {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Fail, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Not configured".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-AUTH-001",
                        "Collaboration",
                        "SharePoint Authentication",
                        "Legacy Authentication Protocols",
                        "Check that legacy authentication protocols are disabled for SharePoint",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-AUTH-001"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Disable legacy authentication protocols in SharePoint admin center > Policies > Access control > Apps that don't use modern authentication".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-AUTH-001",
                        "Collaboration",
                        "SharePoint Authentication",
                        "Legacy Authentication Protocols",
                        "Check that legacy authentication protocols are disabled for SharePoint",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-AUTH-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SYNC-001: OneDrive sync domain restriction
        match &spo_settings {
            Ok(spo) => {
                let sync_restricted = spo
                    .get("isSyncRestricted")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        spo.get("isUnmanagedSyncAppForTenantRestricted")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match sync_restricted {
                    Some(true) => (
                        FindingStatus::Pass,
                        "Restricted to managed devices".to_string(),
                    ),
                    Some(false) => (FindingStatus::Fail, "Not restricted".to_string()),
                    None => (FindingStatus::Review, "Not configured".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SYNC-001",
                        "Collaboration",
                        "SharePoint Sync",
                        "OneDrive Sync Domain Restriction",
                        "Check that OneDrive sync is restricted to managed/domain-joined devices",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SYNC-001"))
                    .current_value(current)
                    .expected_value("Restricted to managed devices".to_string())
                    .remediation("Restrict OneDrive sync to domain-joined or compliant devices in SharePoint admin center > Settings > Sync".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SYNC-001",
                        "Collaboration",
                        "SharePoint Sync",
                        "OneDrive Sync Domain Restriction",
                        "Check that OneDrive sync is restricted to managed/domain-joined devices",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SYNC-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Restricted to managed devices".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SCRIPT-001: Custom scripts disabled
        match &spo_settings {
            Ok(spo) => {
                let custom_script = spo.get("isCustomScriptEnabled").and_then(|v| v.as_bool());

                let (status, current): (FindingStatus, String) = match custom_script {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Fail, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Not configured".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SCRIPT-001",
                        "Collaboration",
                        "SharePoint Security",
                        "Custom Scripts",
                        "Check that custom scripts are disabled on SharePoint sites",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SCRIPT-001"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Disable custom scripts in SharePoint admin center > Settings > Custom Script".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SCRIPT-001",
                        "Collaboration",
                        "SharePoint Security",
                        "Custom Scripts",
                        "Check that custom scripts are disabled on SharePoint sites",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SCRIPT-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-MALWARE-002: Malware scanning on upload
        match &spo_settings {
            Ok(spo) => {
                let malware_scan = spo.get("isMalwareScanEnabled").and_then(|v| v.as_bool());

                let (status, current): (FindingStatus, String) = match malware_scan {
                    Some(true) => (FindingStatus::Pass, "Enabled".to_string()),
                    Some(false) => (FindingStatus::Fail, "Disabled".to_string()),
                    None => (FindingStatus::Review, "Not configured".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-MALWARE-002",
                        "Collaboration",
                        "SharePoint Security",
                        "Malware Scanning on Upload",
                        "Check that files uploaded to SharePoint are scanned for malware",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-MALWARE-002"))
                    .current_value(current)
                    .expected_value("Enabled".to_string())
                    .remediation("Enable malware scanning for uploaded files via Safe Attachments for SharePoint, OneDrive, and Teams in Microsoft Defender portal".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-MALWARE-002",
                        "Collaboration",
                        "SharePoint Security",
                        "Malware Scanning on Upload",
                        "Check that files uploaded to SharePoint are scanned for malware",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-MALWARE-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Enabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // --- Teams Settings ---
        let teams_settings = graph.get_json("/beta/teamwork").await;
        if let Ok(ref teams) = teams_settings {
            raw_data["teamsSettings"] = teams.clone();
        }

        // TEAMS-EXTACCESS-001: External access/federation settings
        match &teams_settings {
            Ok(teams) => {
                let external_access = teams
                    .get("externalAccess")
                    .or_else(|| teams.get("federationConfiguration"));

                let (status, current): (FindingStatus, String) = if let Some(ext) = external_access
                {
                    let allow_all = ext
                        .get("allowAllExternalDomains")
                        .and_then(|v| v.as_bool())
                        .or_else(|| ext.get("allowFederatedUsers").and_then(|v| v.as_bool()));

                    match allow_all {
                        Some(false) => (
                            FindingStatus::Pass,
                            "External access restricted".to_string(),
                        ),
                        Some(true) => (
                            FindingStatus::Fail,
                            "All external domains allowed".to_string(),
                        ),
                        None => (FindingStatus::Review, format!("Configuration: {}", ext)),
                    }
                } else {
                    (
                        FindingStatus::Review,
                        "External access settings not found in response".to_string(),
                    )
                };

                findings.push(
                    Finding::new(
                        "TEAMS-EXTACCESS-001",
                        "Collaboration",
                        "Teams External Access",
                        "Federation Settings",
                        "Check that Teams external access is restricted to approved domains",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-EXTACCESS-001"))
                    .current_value(current)
                    .expected_value("External access restricted to approved domains".to_string())
                    .remediation("Restrict Teams external access to specific allowed domains in Teams admin center > Users > External access".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-EXTACCESS-001",
                        "Collaboration",
                        "Teams External Access",
                        "Federation Settings",
                        "Check that Teams external access is restricted to approved domains",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-EXTACCESS-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("External access restricted to approved domains".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-EXTACCESS-002: Skype consumer communication disabled
        match &teams_settings {
            Ok(teams) => {
                let skype_allowed = teams
                    .get("externalAccess")
                    .and_then(|ext| ext.get("allowSkypeForBusinessUsers"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| teams.get("allowSkypeForConsumer").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match skype_allowed {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Fail, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-EXTACCESS-002",
                        "Collaboration",
                        "Teams External Access",
                        "Skype Consumer Communication",
                        "Check that communication with Skype consumer users is disabled",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-EXTACCESS-002"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Disable Skype consumer communication in Teams admin center > Users > External access > Skype users".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-EXTACCESS-002",
                        "Collaboration",
                        "Teams External Access",
                        "Skype Consumer Communication",
                        "Check that communication with Skype consumer users is disabled",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-EXTACCESS-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-001: Anonymous meeting join restricted
        match &teams_settings {
            Ok(teams) => {
                let anon_join = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("allowAnonymousUsersToJoinMeeting"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        teams
                            .get("allowAnonymousMeetingJoin")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match anon_join {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Warning, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-001",
                        "Collaboration",
                        "Teams Meetings",
                        "Anonymous Meeting Join",
                        "Check that anonymous users cannot join meetings without restrictions",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-001"))
                    .current_value(current)
                    .expected_value("Disabled or restricted".to_string())
                    .remediation("Restrict anonymous meeting join in Teams admin center > Meetings > Meeting settings".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-001",
                        "Collaboration",
                        "Teams Meetings",
                        "Anonymous Meeting Join",
                        "Check that anonymous users cannot join meetings without restrictions",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled or restricted".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-002: Lobby bypass restricted
        match &teams_settings {
            Ok(teams) => {
                let lobby_bypass = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("autoAdmittedUsers"))
                    .and_then(|v| v.as_str())
                    .or_else(|| teams.get("autoAdmittedUsers").and_then(|v| v.as_str()));

                let (status, current): (FindingStatus, String) = match lobby_bypass {
                    Some("everyoneInCompany")
                    | Some("invitedUsersInTenantOnly")
                    | Some("organizationOnly") => {
                        (FindingStatus::Pass, lobby_bypass.unwrap().to_string())
                    }
                    Some("everyone") | Some("everyoneIncludingAnonymous") => {
                        (FindingStatus::Fail, lobby_bypass.unwrap().to_string())
                    }
                    Some(other) => (FindingStatus::Review, other.to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-002",
                        "Collaboration",
                        "Teams Meetings",
                        "Meeting Lobby Bypass",
                        "Check that meeting lobby bypass is restricted to organization users",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-002"))
                    .current_value(current)
                    .expected_value("Organization users only or more restrictive".to_string())
                    .remediation("Set auto-admitted users to 'People in my org' or more restrictive in Teams admin center > Meetings > Meeting policies".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-002",
                        "Collaboration",
                        "Teams Meetings",
                        "Meeting Lobby Bypass",
                        "Check that meeting lobby bypass is restricted to organization users",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Organization users only or more restrictive".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-003: External presenter restrictions
        match &teams_settings {
            Ok(teams) => {
                let presenter_role = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("allowExternalParticipantsToPresent"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        teams
                            .get("allowExternalParticipantsToPresent")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match presenter_role {
                    Some(false) => (
                        FindingStatus::Pass,
                        "External presenters restricted".to_string(),
                    ),
                    Some(true) => (
                        FindingStatus::Warning,
                        "External presenters allowed".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-003",
                        "Collaboration",
                        "Teams Meetings",
                        "External Presenter Restrictions",
                        "Check that external participants are restricted from presenting in meetings",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-003"))
                    .current_value(current)
                    .expected_value("External presenters restricted".to_string())
                    .remediation("Restrict who can present in meetings to organization users in Teams admin center > Meetings > Meeting policies".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-003",
                        "Collaboration",
                        "Teams Meetings",
                        "External Presenter Restrictions",
                        "Check that external participants are restricted from presenting in meetings",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-003"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("External presenters restricted".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-APPS-001: Third-party apps restricted
        match &teams_settings {
            Ok(teams) => {
                let third_party = teams
                    .get("appSettings")
                    .and_then(|a| a.get("allowThirdPartyApps"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| teams.get("allowThirdPartyApps").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match third_party {
                    Some(false) => (FindingStatus::Pass, "Restricted".to_string()),
                    Some(true) => (FindingStatus::Warning, "Allowed".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-APPS-001",
                        "Collaboration",
                        "Teams Apps",
                        "Third-Party Apps",
                        "Check that third-party app installation is restricted in Teams",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-APPS-001"))
                    .current_value(current)
                    .expected_value("Restricted".to_string())
                    .remediation("Restrict third-party apps in Teams admin center > Teams apps > Permission policies".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-APPS-001",
                        "Collaboration",
                        "Teams Apps",
                        "Third-Party Apps",
                        "Check that third-party app installation is restricted in Teams",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-APPS-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Restricted".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-APPS-002: Custom app sideloading restricted
        match &teams_settings {
            Ok(teams) => {
                let sideloading = teams
                    .get("appSettings")
                    .and_then(|a| a.get("allowSideloading"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| teams.get("allowSideloading").and_then(|v| v.as_bool()))
                    .or_else(|| teams.get("isSideloadingAllowed").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match sideloading {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Fail, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-APPS-002",
                        "Collaboration",
                        "Teams Apps",
                        "Custom App Sideloading",
                        "Check that custom app sideloading is restricted in Teams",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-APPS-002"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Disable custom app sideloading in Teams admin center > Teams apps > Setup policies".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-APPS-002",
                        "Collaboration",
                        "Teams Apps",
                        "Custom App Sideloading",
                        "Check that custom app sideloading is restricted in Teams",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-APPS-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-CLIENT-001: Email integration settings
        match &teams_settings {
            Ok(teams) => {
                let email_integration = teams
                    .get("emailIntegration")
                    .and_then(|e| e.get("allowEmailIntoChannel"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| teams.get("allowEmailIntoChannel").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match email_integration {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Warning, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-CLIENT-001",
                        "Collaboration",
                        "Teams Client",
                        "Email Integration",
                        "Check email integration settings for Teams channels",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-CLIENT-001"))
                    .current_value(current)
                    .expected_value("Disabled or restricted".to_string())
                    .remediation("Review email integration settings in Teams admin center > Teams settings > Email integration".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-CLIENT-001",
                        "Collaboration",
                        "Teams Client",
                        "Email Integration",
                        "Check email integration settings for Teams channels",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-CLIENT-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled or restricted".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // --- Forms Settings ---
        let forms_settings = graph.get_json("/beta/admin/forms/settings").await;
        if let Ok(ref forms) = forms_settings {
            raw_data["formsSettings"] = forms.clone();
        }

        // FORMS-CONFIG-001: External sharing restricted
        match &forms_settings {
            Ok(forms) => {
                let external_sharing = forms
                    .get("isExternalSharingEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        forms
                            .get("externalSharingEnabled")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match external_sharing {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Warning, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-001",
                        "Collaboration",
                        "Forms Configuration",
                        "External Sharing",
                        "Check that Microsoft Forms external sharing is restricted",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-001"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Restrict external sharing in Microsoft Forms admin settings > External sharing".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-001",
                        "Collaboration",
                        "Forms Configuration",
                        "External Sharing",
                        "Check that Microsoft Forms external sharing is restricted",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("FORMS-CONFIG-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // FORMS-CONFIG-002: External collaboration settings
        match &forms_settings {
            Ok(forms) => {
                let external_collab = forms
                    .get("isExternalCollaborationEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        forms
                            .get("externalCollaborationEnabled")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match external_collab {
                    Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                    Some(true) => (FindingStatus::Warning, "Enabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-002",
                        "Collaboration",
                        "Forms Configuration",
                        "External Collaboration",
                        "Check that external collaboration settings are appropriately configured for Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-002"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Restrict external collaboration in Microsoft Forms admin settings".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-002",
                        "Collaboration",
                        "Forms Configuration",
                        "External Collaboration",
                        "Check that external collaboration settings are appropriately configured for Forms",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("FORMS-CONFIG-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // FORMS-CONFIG-003: Record respondent names
        match &forms_settings {
            Ok(forms) => {
                let record_names = forms
                    .get("isRecordIdentityByDefaultEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        forms
                            .get("recordIdentityByDefault")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match record_names {
                    Some(true) => (FindingStatus::Pass, "Enabled".to_string()),
                    Some(false) => (FindingStatus::Warning, "Disabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-003",
                        "Collaboration",
                        "Forms Configuration",
                        "Record Respondent Names",
                        "Check that respondent names are recorded by default in Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-003"))
                    .current_value(current)
                    .expected_value("Enabled".to_string())
                    .remediation(
                        "Enable 'Record name by default' in Microsoft Forms admin settings"
                            .to_string(),
                    )
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-003",
                        "Collaboration",
                        "Forms Configuration",
                        "Record Respondent Names",
                        "Check that respondent names are recorded by default in Forms",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("FORMS-CONFIG-003"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Enabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // FORMS-CONFIG-004: Phishing protection enabled
        match &forms_settings {
            Ok(forms) => {
                let phishing_protection = forms
                    .get("isInternalPhishingProtectionEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        forms
                            .get("internalPhishingProtectionEnabled")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match phishing_protection {
                    Some(true) => (FindingStatus::Pass, "Enabled".to_string()),
                    Some(false) => (FindingStatus::Fail, "Disabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-004",
                        "Collaboration",
                        "Forms Configuration",
                        "Phishing Protection",
                        "Check that internal phishing protection is enabled for Microsoft Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-004"))
                    .current_value(current)
                    .expected_value("Enabled".to_string())
                    .remediation("Enable phishing protection in Microsoft Forms admin settings to detect and block phishing attempts".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-004",
                        "Collaboration",
                        "Forms Configuration",
                        "Phishing Protection",
                        "Check that internal phishing protection is enabled for Microsoft Forms",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("FORMS-CONFIG-004"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Enabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SHARING-007: Default sharing permissions are View not Edit
        match &spo_settings {
            Ok(spo) => {
                let link_type = spo
                    .get("defaultSharingLinkType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let link_perm = spo
                    .get("defaultLinkPermission")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let (status, current): (FindingStatus, String) = match (link_type, link_perm) {
                    (_, "view") => (
                        FindingStatus::Pass,
                        format!("linkType={}, permission=view", link_type),
                    ),
                    (_, "edit") => (
                        FindingStatus::Fail,
                        format!("linkType={}, permission=edit", link_type),
                    ),
                    _ => (
                        FindingStatus::Review,
                        format!("linkType={}, permission={}", link_type, link_perm),
                    ),
                };

                findings.push(
                    Finding::new(
                        "SPO-SHARING-007",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Default Sharing Permissions",
                        "Verify that default sharing permissions are set to View rather than Edit",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SHARING-007"))
                    .current_value(current)
                    .expected_value("View".to_string())
                    .remediation("Set default sharing link permission to 'View' in SharePoint admin center > Policies > Sharing to prevent unintended edit access".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SHARING-007",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Default Sharing Permissions",
                        "Verify that default sharing permissions are set to View rather than Edit",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SHARING-007"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("View".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SHARING-008: Anonymous link expiration configured
        match &spo_settings {
            Ok(spo) => {
                let anon_link_expiration = spo
                    .get("sharingAnonymousLinkExpirationInDays")
                    .and_then(|v| v.as_i64())
                    .or_else(|| {
                        spo.get("anonymousLinkExpirationInDays")
                            .and_then(|v| v.as_i64())
                    });

                let (status, current): (FindingStatus, String) = match anon_link_expiration {
                    Some(days) if days > 0 && days <= 30 => {
                        (FindingStatus::Pass, format!("{} days", days))
                    }
                    Some(days) if days > 30 && days <= 90 => {
                        (FindingStatus::Warning, format!("{} days (>30)", days))
                    }
                    Some(days) if days > 90 => {
                        (FindingStatus::Fail, format!("{} days (>90)", days))
                    }
                    Some(0) => (FindingStatus::Fail, "No expiration (0 days)".to_string()),
                    None => (FindingStatus::Review, "Not configured".to_string()),
                    Some(days) => (FindingStatus::Review, format!("{} days", days)),
                };

                findings.push(
                    Finding::new(
                        "SPO-SHARING-008",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Anonymous Link Expiration",
                        "Check that anonymous sharing links have an expiration configured",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SHARING-008"))
                    .current_value(current)
                    .expected_value("Expiration <= 30 days".to_string())
                    .remediation("Configure anonymous link expiration to 30 days or less in SharePoint admin center > Policies > Sharing".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SHARING-008",
                        "Collaboration",
                        "SharePoint Sharing",
                        "Anonymous Link Expiration",
                        "Check that anonymous sharing links have an expiration configured",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SHARING-008"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Expiration <= 30 days".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-B2B-001: B2B integration for SharePoint/OneDrive
        match &spo_settings {
            Ok(spo) => {
                let sharing_capability = spo
                    .get("sharingCapability")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let b2b_enabled = spo
                    .get("isB2BIntegrationEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        spo.get("enableAzureADB2BIntegration")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) =
                    match (sharing_capability, b2b_enabled) {
                        ("disabled", _) => {
                            (FindingStatus::Pass, "External sharing disabled".to_string())
                        }
                        (_, Some(true)) => (
                            FindingStatus::Pass,
                            format!("B2B integration enabled, sharing={}", sharing_capability),
                        ),
                        (_, Some(false)) => (
                            FindingStatus::Fail,
                            format!("B2B integration disabled, sharing={}", sharing_capability),
                        ),
                        (_, None) => (
                            FindingStatus::Review,
                            format!("B2B integration unknown, sharing={}", sharing_capability),
                        ),
                    };

                findings.push(
                    Finding::new(
                        "SPO-B2B-001",
                        "Collaboration",
                        "SharePoint B2B Integration",
                        "Azure AD B2B Integration",
                        "Check that B2B integration is enabled for SharePoint and OneDrive external sharing",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-B2B-001"))
                    .current_value(current)
                    .expected_value("B2B integration enabled when external sharing is active".to_string())
                    .remediation("Enable Azure AD B2B integration in SharePoint admin center > Policies > Sharing > Advanced settings to leverage B2B guest accounts".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-B2B-001",
                        "Collaboration",
                        "SharePoint B2B Integration",
                        "Azure AD B2B Integration",
                        "Check that B2B integration is enabled for SharePoint and OneDrive external sharing",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-B2B-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("B2B integration enabled when external sharing is active".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SYNC-002: Block sync for specific file types
        match &spo_settings {
            Ok(spo) => {
                let excluded_extensions = spo
                    .get("excludedFileExtensionsForSyncApp")
                    .and_then(|v| v.as_array())
                    .or_else(|| spo.get("excludedFileExtensions").and_then(|v| v.as_array()));

                let (status, current): (FindingStatus, String) = match excluded_extensions {
                    Some(exts) if !exts.is_empty() => (
                        FindingStatus::Pass,
                        format!("{} file types blocked from sync", exts.len()),
                    ),
                    Some(_) => (FindingStatus::Fail, "Empty exclusion list".to_string()),
                    None => (FindingStatus::Review, "Not configured".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SYNC-002",
                        "Collaboration",
                        "SharePoint Sync",
                        "Blocked Sync File Types",
                        "Check that sync is blocked for specific risky file types",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SYNC-002"))
                    .current_value(current)
                    .expected_value("Risky file types excluded from sync".to_string())
                    .remediation("Configure excluded file extensions for the sync app in SharePoint admin center > Settings > Sync > Block syncing of specific file types".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SYNC-002",
                        "Collaboration",
                        "SharePoint Sync",
                        "Blocked Sync File Types",
                        "Check that sync is blocked for specific risky file types",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SYNC-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Risky file types excluded from sync".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-SCRIPT-002: Custom script on team sites disabled
        match &spo_settings {
            Ok(spo) => {
                let custom_script_sites = spo
                    .get("isCustomScriptEnabledOnSelfServiceCreatedSites")
                    .and_then(|v| v.as_bool())
                    .or_else(|| spo.get("isCustomScriptEnabled").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match custom_script_sites {
                    Some(false) => (FindingStatus::Pass, "Disabled on team sites".to_string()),
                    Some(true) => (FindingStatus::Fail, "Enabled on team sites".to_string()),
                    None => (FindingStatus::Review, "Not configured".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-SCRIPT-002",
                        "Collaboration",
                        "SharePoint Security",
                        "Custom Scripts on Team Sites",
                        "Check that custom scripts are disabled on self-service created team sites",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-SCRIPT-002"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Disable custom scripts on team sites via Set-SPOSite or SharePoint admin center > Settings > Custom Script".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-SCRIPT-002",
                        "Collaboration",
                        "SharePoint Security",
                        "Custom Scripts on Team Sites",
                        "Check that custom scripts are disabled on self-service created team sites",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-SCRIPT-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-OD-001: OneDrive access restricted to licensed users
        match &spo_settings {
            Ok(spo) => {
                let od_licensed_only = spo
                    .get("isOneDriveForGuestsEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        spo.get("oneDriveForGuestsEnabled")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match od_licensed_only {
                    Some(false) => (
                        FindingStatus::Pass,
                        "Guest OneDrive access disabled".to_string(),
                    ),
                    Some(true) => (
                        FindingStatus::Warning,
                        "Guest OneDrive access enabled".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-OD-001",
                        "Collaboration",
                        "OneDrive",
                        "OneDrive Access Restriction",
                        "Check that OneDrive access is restricted to licensed users only",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-OD-001"))
                    .current_value(current)
                    .expected_value("OneDrive restricted to licensed users".to_string())
                    .remediation("Restrict OneDrive provisioning to licensed users and disable guest OneDrive access in SharePoint admin center".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-OD-001",
                        "Collaboration",
                        "OneDrive",
                        "OneDrive Access Restriction",
                        "Check that OneDrive access is restricted to licensed users only",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-OD-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("OneDrive restricted to licensed users".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-LOOP-001: Loop workspace creation settings
        match &spo_settings {
            Ok(spo) => {
                let loop_enabled = spo
                    .get("isLoopEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| spo.get("isFluidEnabled").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match loop_enabled {
                    Some(false) => (FindingStatus::Pass, "Loop workspaces disabled".to_string()),
                    Some(true) => (
                        FindingStatus::Warning,
                        "Loop workspaces enabled".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-LOOP-001",
                        "Collaboration",
                        "Loop Workspaces",
                        "Loop Workspace Creation",
                        "Check that Loop workspace creation is appropriately controlled",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-LOOP-001"))
                    .current_value(current)
                    .expected_value("Loop workspaces disabled or restricted".to_string())
                    .remediation("Control Loop workspace creation in SharePoint admin center > Settings > Loop or via Set-SPOTenant".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-LOOP-001",
                        "Collaboration",
                        "Loop Workspaces",
                        "Loop Workspace Creation",
                        "Check that Loop workspace creation is appropriately controlled",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-LOOP-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Loop workspaces disabled or restricted".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // SPO-LOOP-002: Loop external sharing settings
        match &spo_settings {
            Ok(spo) => {
                let loop_external = spo
                    .get("isLoopExternalSharingEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        spo.get("isFluidExternalSharingEnabled")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match loop_external {
                    Some(false) => (
                        FindingStatus::Pass,
                        "Loop external sharing disabled".to_string(),
                    ),
                    Some(true) => (
                        FindingStatus::Fail,
                        "Loop external sharing enabled".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "SPO-LOOP-002",
                        "Collaboration",
                        "Loop Workspaces",
                        "Loop External Sharing",
                        "Check that Loop external sharing is restricted",
                    )
                    .status(status)
                    .severity(registry.get_severity("SPO-LOOP-002"))
                    .current_value(current)
                    .expected_value("Loop external sharing disabled".to_string())
                    .remediation("Disable external sharing for Loop components in SharePoint admin center > Settings > Loop".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "SPO-LOOP-002",
                        "Collaboration",
                        "Loop Workspaces",
                        "Loop External Sharing",
                        "Check that Loop external sharing is restricted",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("SPO-LOOP-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Loop external sharing disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-EXTACCESS-003: External user access to channels
        match &teams_settings {
            Ok(teams) => {
                let ext_channel_access = teams
                    .get("externalAccess")
                    .and_then(|ext| ext.get("allowExternalUsersToAccessChannels"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        teams
                            .get("allowExternalUsersInChannels")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match ext_channel_access {
                    Some(false) => (
                        FindingStatus::Pass,
                        "External channel access disabled".to_string(),
                    ),
                    Some(true) => (
                        FindingStatus::Warning,
                        "External channel access enabled".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-EXTACCESS-003",
                        "Collaboration",
                        "Teams External Access",
                        "External User Channel Access",
                        "Check that external user access to channels is appropriately restricted",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-EXTACCESS-003"))
                    .current_value(current)
                    .expected_value("External channel access restricted".to_string())
                    .remediation("Restrict external user access to shared channels in Teams admin center > Teams > Teams settings".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-EXTACCESS-003",
                        "Collaboration",
                        "Teams External Access",
                        "External User Channel Access",
                        "Check that external user access to channels is appropriately restricted",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-EXTACCESS-003"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("External channel access restricted".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-EXTACCESS-004: Unmanaged external access restrictions
        match &teams_settings {
            Ok(teams) => {
                let unmanaged_access = teams
                    .get("externalAccess")
                    .and_then(|ext| ext.get("allowTeamsConsumer"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        teams
                            .get("allowTeamsConsumerInbound")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match unmanaged_access {
                    Some(false) => (
                        FindingStatus::Pass,
                        "Unmanaged Teams access blocked".to_string(),
                    ),
                    Some(true) => (
                        FindingStatus::Fail,
                        "Unmanaged Teams access allowed".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-EXTACCESS-004",
                        "Collaboration",
                        "Teams External Access",
                        "Unmanaged External Access",
                        "Check that communication with unmanaged Teams accounts is restricted",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-EXTACCESS-004"))
                    .current_value(current)
                    .expected_value("Unmanaged Teams access blocked".to_string())
                    .remediation("Disable communication with unmanaged Teams users in Teams admin center > Users > External access > Teams accounts not managed by an organization".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-EXTACCESS-004",
                        "Collaboration",
                        "Teams External Access",
                        "Unmanaged External Access",
                        "Check that communication with unmanaged Teams accounts is restricted",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-EXTACCESS-004"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Unmanaged Teams access blocked".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-004: Cloud recording settings
        match &teams_settings {
            Ok(teams) => {
                let cloud_recording = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("allowCloudRecording"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| teams.get("allowCloudRecording").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match cloud_recording {
                    Some(false) => (FindingStatus::Pass, "Cloud recording disabled".to_string()),
                    Some(true) => (
                        FindingStatus::Warning,
                        "Cloud recording enabled".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-004",
                        "Collaboration",
                        "Teams Meetings",
                        "Cloud Recording",
                        "Check that cloud recording settings are appropriately configured",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-004"))
                    .current_value(current)
                    .expected_value("Cloud recording restricted or disabled".to_string())
                    .remediation("Configure cloud recording policies in Teams admin center > Meetings > Meeting policies > Recording & transcription".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-004",
                        "Collaboration",
                        "Teams Meetings",
                        "Cloud Recording",
                        "Check that cloud recording settings are appropriately configured",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-004"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Cloud recording restricted or disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-005: Transcription settings
        match &teams_settings {
            Ok(teams) => {
                let transcription = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("allowTranscription"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| teams.get("allowTranscription").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match transcription {
                    Some(false) => (FindingStatus::Pass, "Transcription disabled".to_string()),
                    Some(true) => (FindingStatus::Warning, "Transcription enabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-005",
                        "Collaboration",
                        "Teams Meetings",
                        "Meeting Transcription",
                        "Check that meeting transcription is appropriately restricted",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-005"))
                    .current_value(current)
                    .expected_value("Transcription restricted or disabled".to_string())
                    .remediation("Configure transcription settings in Teams admin center > Meetings > Meeting policies > Recording & transcription".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-005",
                        "Collaboration",
                        "Teams Meetings",
                        "Meeting Transcription",
                        "Check that meeting transcription is appropriately restricted",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-005"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Transcription restricted or disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-006: Dial-in users bypass lobby
        match &teams_settings {
            Ok(teams) => {
                let dialin_bypass = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("allowPSTNUsersToBypassLobby"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        teams
                            .get("allowPSTNUsersToBypassLobby")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match dialin_bypass {
                    Some(false) => (
                        FindingStatus::Pass,
                        "Dial-in users wait in lobby".to_string(),
                    ),
                    Some(true) => (
                        FindingStatus::Fail,
                        "Dial-in users bypass lobby".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-006",
                        "Collaboration",
                        "Teams Meetings",
                        "Dial-in Lobby Bypass",
                        "Check that dial-in (PSTN) users cannot bypass the meeting lobby",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-006"))
                    .current_value(current)
                    .expected_value("Dial-in users wait in lobby".to_string())
                    .remediation("Disable PSTN lobby bypass in Teams admin center > Meetings > Meeting policies > Participants & guests".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-006",
                        "Collaboration",
                        "Teams Meetings",
                        "Dial-in Lobby Bypass",
                        "Check that dial-in (PSTN) users cannot bypass the meeting lobby",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-006"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Dial-in users wait in lobby".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-007: External participant control sharing
        match &teams_settings {
            Ok(teams) => {
                let ext_control = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("allowExternalParticipantGiveRequestControl"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        teams
                            .get("allowExternalParticipantGiveRequestControl")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match ext_control {
                    Some(false) => (
                        FindingStatus::Pass,
                        "External control sharing disabled".to_string(),
                    ),
                    Some(true) => (
                        FindingStatus::Warning,
                        "External control sharing enabled".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-007",
                        "Collaboration",
                        "Teams Meetings",
                        "External Participant Control",
                        "Check that external participants cannot give or request control in meetings",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-007"))
                    .current_value(current)
                    .expected_value("External control sharing disabled".to_string())
                    .remediation("Disable external participant control sharing in Teams admin center > Meetings > Meeting policies > Content sharing".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-007",
                        "Collaboration",
                        "Teams Meetings",
                        "External Participant Control",
                        "Check that external participants cannot give or request control in meetings",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-007"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("External control sharing disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-008: Meeting chat restrictions
        match &teams_settings {
            Ok(teams) => {
                let meeting_chat = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("meetingChatEnabledType"))
                    .and_then(|v| v.as_str())
                    .or_else(|| teams.get("meetingChatEnabledType").and_then(|v| v.as_str()));

                let (status, current): (FindingStatus, String) = match meeting_chat {
                    Some("disabled") => (FindingStatus::Pass, "Meeting chat disabled".to_string()),
                    Some("enabledForEveryone") => (
                        FindingStatus::Warning,
                        "Chat enabled for everyone".to_string(),
                    ),
                    Some("enabledExceptAnonymous") => (
                        FindingStatus::Pass,
                        "Chat disabled for anonymous users".to_string(),
                    ),
                    Some(other) => (FindingStatus::Review, other.to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-008",
                        "Collaboration",
                        "Teams Meetings",
                        "Meeting Chat Restrictions",
                        "Check that meeting chat is appropriately restricted for anonymous users",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-008"))
                    .current_value(current)
                    .expected_value("Chat disabled for anonymous users or more restrictive".to_string())
                    .remediation("Configure meeting chat to exclude anonymous users in Teams admin center > Meetings > Meeting policies".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-008",
                        "Collaboration",
                        "Teams Meetings",
                        "Meeting Chat Restrictions",
                        "Check that meeting chat is appropriately restricted for anonymous users",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-008"))
                    .current_value(format!("Error: {}", e))
                    .expected_value(
                        "Chat disabled for anonymous users or more restrictive".to_string(),
                    )
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-MEETING-009: Watermark for screen sharing
        match &teams_settings {
            Ok(teams) => {
                let watermark = teams
                    .get("meetingSettings")
                    .and_then(|m| m.get("allowWatermarkForScreenSharing"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        teams
                            .get("allowWatermarkForScreenSharing")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match watermark {
                    Some(true) => (FindingStatus::Pass, "Watermark enabled".to_string()),
                    Some(false) => (FindingStatus::Warning, "Watermark disabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-009",
                        "Collaboration",
                        "Teams Meetings",
                        "Screen Sharing Watermark",
                        "Check that watermark is available for screen sharing in meetings",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-MEETING-009"))
                    .current_value(current)
                    .expected_value("Watermark enabled".to_string())
                    .remediation("Enable watermark for screen sharing in Teams admin center > Meetings > Meeting policies > Content sharing".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-MEETING-009",
                        "Collaboration",
                        "Teams Meetings",
                        "Screen Sharing Watermark",
                        "Check that watermark is available for screen sharing in meetings",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-MEETING-009"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Watermark enabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-CLIENT-002: Third-party cloud storage integration
        match &teams_settings {
            Ok(teams) => {
                let cloud_storage = teams
                    .get("clientSettings")
                    .and_then(|c| c.get("allowThirdPartyStorage"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| teams.get("allowDropBox").and_then(|v| v.as_bool()))
                    .or_else(|| teams.get("allowGoogleDrive").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match cloud_storage {
                    Some(false) => (
                        FindingStatus::Pass,
                        "Third-party storage disabled".to_string(),
                    ),
                    Some(true) => (
                        FindingStatus::Fail,
                        "Third-party storage enabled".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-CLIENT-002",
                        "Collaboration",
                        "Teams Client",
                        "Third-Party Cloud Storage",
                        "Check that third-party cloud storage integration is disabled in Teams",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-CLIENT-002"))
                    .current_value(current)
                    .expected_value("Third-party storage disabled".to_string())
                    .remediation("Disable third-party cloud storage (Dropbox, Google Drive, Box, etc.) in Teams admin center > Teams > Teams settings > Files".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-CLIENT-002",
                        "Collaboration",
                        "Teams Client",
                        "Third-Party Cloud Storage",
                        "Check that third-party cloud storage integration is disabled in Teams",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-CLIENT-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Third-party storage disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-INFO-001: Information barriers
        match &teams_settings {
            Ok(teams) => {
                let info_barriers = teams
                    .get("informationBarriers")
                    .and_then(|ib| ib.get("mode"))
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        teams
                            .get("informationBarriersMode")
                            .and_then(|v| v.as_str())
                    });

                let (status, current): (FindingStatus, String) = match info_barriers {
                    Some("enabled") | Some("explicit") | Some("implicit") => (
                        FindingStatus::Pass,
                        format!("Information barriers: {}", info_barriers.unwrap()),
                    ),
                    Some("disabled") | Some("open") => (
                        FindingStatus::Warning,
                        "Information barriers not active".to_string(),
                    ),
                    Some(other) => (FindingStatus::Review, other.to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-INFO-001",
                        "Collaboration",
                        "Teams Compliance",
                        "Information Barriers",
                        "Check that information barriers are configured for Teams if required",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-INFO-001"))
                    .current_value(current)
                    .expected_value("Information barriers enabled if required by compliance".to_string())
                    .remediation("Configure information barriers in Microsoft Purview if required by your compliance framework to prevent unauthorized communication between groups".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-INFO-001",
                        "Collaboration",
                        "Teams Compliance",
                        "Information Barriers",
                        "Check that information barriers are configured for Teams if required",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-INFO-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value(
                        "Information barriers enabled if required by compliance".to_string(),
                    )
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // TEAMS-REPORTING-001: Reporting policies for usage analytics
        match &teams_settings {
            Ok(teams) => {
                let reporting = teams
                    .get("reportingSettings")
                    .and_then(|r| r.get("allowUserReporting"))
                    .and_then(|v| v.as_bool())
                    .or_else(|| teams.get("isReportingEnabled").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match reporting {
                    Some(true) => (FindingStatus::Pass, "Reporting enabled".to_string()),
                    Some(false) => (FindingStatus::Fail, "Reporting disabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "TEAMS-REPORTING-001",
                        "Collaboration",
                        "Teams Administration",
                        "Reporting Policies",
                        "Check that Teams reporting and user feedback policies are enabled",
                    )
                    .status(status)
                    .severity(registry.get_severity("TEAMS-REPORTING-001"))
                    .current_value(current)
                    .expected_value("Reporting enabled".to_string())
                    .remediation("Enable Teams usage reporting and user feedback reporting in Teams admin center > Analytics & reports".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TEAMS-REPORTING-001",
                        "Collaboration",
                        "Teams Administration",
                        "Reporting Policies",
                        "Check that Teams reporting and user feedback policies are enabled",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("TEAMS-REPORTING-001"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Reporting enabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // FORMS-CONFIG-005: Bing search integration
        match &forms_settings {
            Ok(forms) => {
                let bing_search = forms
                    .get("isBingSearchEnabled")
                    .and_then(|v| v.as_bool())
                    .or_else(|| forms.get("bingSearchEnabled").and_then(|v| v.as_bool()));

                let (status, current): (FindingStatus, String) = match bing_search {
                    Some(false) => (FindingStatus::Pass, "Bing search disabled".to_string()),
                    Some(true) => (FindingStatus::Warning, "Bing search enabled".to_string()),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-005",
                        "Collaboration",
                        "Forms Configuration",
                        "Bing Search Integration",
                        "Check that Bing search integration is disabled in Microsoft Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-005"))
                    .current_value(current)
                    .expected_value("Bing search disabled".to_string())
                    .remediation("Disable Bing search integration in Microsoft Forms admin settings to prevent data leakage through search suggestions".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-005",
                        "Collaboration",
                        "Forms Configuration",
                        "Bing Search Integration",
                        "Check that Bing search integration is disabled in Microsoft Forms",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("FORMS-CONFIG-005"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Bing search disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        // FORMS-CONFIG-006: Internal survey sharing
        match &forms_settings {
            Ok(forms) => {
                let internal_sharing = forms
                    .get("isInOrgSurveyDefault")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        forms
                            .get("inOrgFormsPhishingScanEnabled")
                            .and_then(|v| v.as_bool())
                    });

                let (status, current): (FindingStatus, String) = match internal_sharing {
                    Some(true) => (
                        FindingStatus::Pass,
                        "Internal-only survey default enabled".to_string(),
                    ),
                    Some(false) => (
                        FindingStatus::Warning,
                        "Internal-only survey default disabled".to_string(),
                    ),
                    None => (FindingStatus::Review, "Setting not found".to_string()),
                };

                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-006",
                        "Collaboration",
                        "Forms Configuration",
                        "Internal Survey Sharing",
                        "Check that survey sharing defaults to internal-only for Microsoft Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-006"))
                    .current_value(current)
                    .expected_value("Internal-only survey default enabled".to_string())
                    .remediation("Set default survey sharing to internal-only in Microsoft Forms admin settings to prevent unintentional external data collection".to_string())
                    .build(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "FORMS-CONFIG-006",
                        "Collaboration",
                        "Forms Configuration",
                        "Internal Survey Sharing",
                        "Check that survey sharing defaults to internal-only for Microsoft Forms",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("FORMS-CONFIG-006"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Internal-only survey default enabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data,
            error: None,
            duration_ms,
        })
    }
}
