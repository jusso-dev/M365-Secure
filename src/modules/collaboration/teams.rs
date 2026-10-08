//! Teams checks (TEAMS-*). Policy settings come from the Teams admin backend (`Get-Cs*` shapes); team
//! inventory comes from Graph groups. Each id tests what its registry name says.
//!
//! | id | source | setting | pass |
//! |---|---|---|---|
//! | TEAMS-EXTACCESS-001 | TenantFederationSettings | AllowTeamsConsumer | false |
//! | TEAMS-EXTACCESS-002 | TenantFederationSettings | AllowTeamsConsumerInbound | false |
//! | TEAMS-EXTACCESS-003 | TenantFederationSettings | AllowFederatedUsers / AllowedDomains | off, or an explicit allow list |
//! | TEAMS-EXTACCESS-004 | TenantFederationSettings | AllowPublicUsers | false |
//! | TEAMS-MEETING-001 | TeamsMeetingPolicy Global | AllowAnonymousUsersToJoinMeeting | false |
//! | TEAMS-MEETING-002 | TeamsMeetingPolicy Global | AllowAnonymousUsersToStartMeeting | false |
//! | TEAMS-MEETING-003 | TeamsMeetingPolicy Global | AutoAdmittedUsers | EveryoneInCompany(ExcludingGuests), InvitedUsers or OrganizerOnly |
//! | TEAMS-MEETING-004 | TeamsMeetingPolicy Global | AllowPSTNUsersToBypassLobby | false |
//! | TEAMS-MEETING-005 | TeamsMeetingPolicy Global | AllowExternalParticipantGiveRequestControl | false |
//! | TEAMS-MEETING-006 | TeamsMeetingPolicy Global | MeetingChatEnabledType | EnabledExceptAnonymous or Disabled |
//! | TEAMS-MEETING-007 | TeamsMeetingPolicy Global | DesignatedPresenterRoleMode | OrganizerOnlyUserOverride |
//! | TEAMS-MEETING-008 | TeamsMeetingPolicy Global | AllowExternalNonTrustedMeetingChat | false |
//! | TEAMS-MEETING-009 | TeamsMeetingPolicy Global | AllowCloudRecording | false |
//! | TEAMS-CLIENT-001 | TeamsClientConfiguration | AllowDropBox/Box/GoogleDrive/ShareFile/Egnyte | all false |
//! | TEAMS-CLIENT-002 | TeamsClientConfiguration | AllowEmailIntoChannel | false |
//! | TEAMS-GUEST-001 | TeamsClientConfiguration | AllowGuestUser | false (Warning when on) |
//! | TEAMS-APPS-001 | Graph teamwork/teamsAppSettings | isChatResourceSpecificConsentEnabled | false |
//! | TEAMS-APPS-002 | TeamsAppPermissionPolicy Global | GlobalCatalogAppsType, PrivateCatalogAppsType | AllowedAppList |
//! | TEAMS-APPS-003 | TeamsAppSetupPolicy Global | AllowSideLoading | false |
//! | TEAMS-REPORTING-001 | TeamsMessagingPolicy Global | AllowSecurityEndUserReporting | true |
//! | TEAMS-PRIVATE-001 | Graph groups (Team) + owners/members | visibility, owner count, guest members | every team has 2+ owners; Warning lists public teams |
//! | TEAMS-INFO-001 | Graph groups (Team) | team count | informational |

use anyhow::Result;
use serde_json::Value;

use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::clients::teams::{self, bool_of, str_of, AllowedDomains, TeamsConfig};
use crate::graph::GraphClient;
use crate::modules::record_one;

const CATEGORY: &str = "Collaboration";
/// Owner and member lookups are two calls per team; beyond this many teams the check samples.
const TEAM_DETAIL_LIMIT: usize = 300;

type Outcome = Result<(FindingStatus, String)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamSummary {
    pub id: String,
    pub display_name: String,
    pub visibility: String,
    pub owners: Option<usize>,
    pub guests: Option<usize>,
}

pub struct TeamsData {
    pub federation: Result<Value>,
    pub client: Result<Value>,
    pub meeting: Result<Value>,
    pub app_permission: Result<Value>,
    pub app_setup: Result<Value>,
    pub messaging: Result<Value>,
    pub app_settings: Result<Value>,
    pub teams: Result<Vec<TeamSummary>>,
    pub raw: Value,
}

pub async fn collect(graph: &GraphClient) -> TeamsData {
    let (federation, client, meeting, app_permission, app_setup, messaging) = tokio::join!(
        teams::get_global(graph, TeamsConfig::TenantFederationSettings),
        teams::get_global(graph, TeamsConfig::TeamsClientConfiguration),
        teams::get_global(graph, TeamsConfig::TeamsMeetingPolicy),
        teams::get_global(graph, TeamsConfig::TeamsAppPermissionPolicy),
        teams::get_global(graph, TeamsConfig::TeamsAppSetupPolicy),
        teams::get_global(graph, TeamsConfig::TeamsMessagingPolicy),
    );
    for (cfg, r) in [
        (TeamsConfig::TenantFederationSettings, &federation),
        (TeamsConfig::TeamsClientConfiguration, &client),
        (TeamsConfig::TeamsMeetingPolicy, &meeting),
        (TeamsConfig::TeamsAppPermissionPolicy, &app_permission),
        (TeamsConfig::TeamsAppSetupPolicy, &app_setup),
        (TeamsConfig::TeamsMessagingPolicy, &messaging),
    ] {
        if let Err(e) = r {
            tracing::warn!("{} unavailable: {e}", cfg.cmdlet());
        }
    }
    let app_settings = graph.get_json("/beta/teamwork/teamsAppSettings").await;
    let teams = collect_teams(graph).await;

    let raw = serde_json::json!({
        "tenantFederationSettings": federation.as_ref().ok(),
        "teamsClientConfiguration": client.as_ref().ok(),
        "teamsMeetingPolicy": meeting.as_ref().ok(),
        "teamsAppPermissionPolicy": app_permission.as_ref().ok(),
        "teamsAppSetupPolicy": app_setup.as_ref().ok(),
        "teamsMessagingPolicy": messaging.as_ref().ok(),
        "teamsAppSettings": app_settings.as_ref().ok(),
        "teamCount": teams.as_ref().ok().map(|t| t.len()),
    });
    TeamsData {
        federation,
        client,
        meeting,
        app_permission,
        app_setup,
        messaging,
        app_settings,
        teams,
        raw,
    }
}

async fn collect_teams(graph: &GraphClient) -> Result<Vec<TeamSummary>> {
    let groups: Vec<Value> = graph
        .get_all("/v1.0/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName,visibility")
        .await?;
    let mut summaries: Vec<TeamSummary> = groups
        .iter()
        .map(|g| TeamSummary {
            id: g["id"].as_str().unwrap_or_default().to_string(),
            display_name: g["displayName"].as_str().unwrap_or_default().to_string(),
            visibility: g["visibility"].as_str().unwrap_or("Unknown").to_string(),
            owners: None,
            guests: None,
        })
        .collect();

    let detail = summaries.len().min(TEAM_DETAIL_LIMIT);
    let lookups = summaries[..detail].iter().map(|t| async move {
        let owners: Result<Vec<Value>> = graph
            .get_all(&format!("/v1.0/groups/{}/owners?$select=id", t.id))
            .await;
        let members: Result<Vec<Value>> = graph
            .get_all(&format!(
                "/v1.0/groups/{}/members?$select=id,userType",
                t.id
            ))
            .await;
        (
            owners.ok().map(|o| o.len()),
            members.ok().map(|m| {
                m.iter()
                    .filter(|u| {
                        u["userType"]
                            .as_str()
                            .is_some_and(|t| t.eq_ignore_ascii_case("Guest"))
                    })
                    .count()
            }),
        )
    });
    let details = futures::future::join_all(lookups).await;
    for (t, (owners, guests)) in summaries.iter_mut().zip(details) {
        t.owners = owners;
        t.guests = guests;
    }
    Ok(summaries)
}

fn ok(r: &Result<Value>) -> Result<&Value> {
    r.as_ref().map_err(|e| anyhow::anyhow!("{e}"))
}

fn need_bool(v: &Value, cfg: TeamsConfig, key: &str) -> Result<bool> {
    bool_of(v, key).ok_or_else(|| anyhow::anyhow!("{} did not include {key}", cfg.cmdlet()))
}

fn need_str<'a>(v: &'a Value, cfg: TeamsConfig, key: &str) -> Result<&'a str> {
    str_of(v, key).ok_or_else(|| anyhow::anyhow!("{} did not include {key}", cfg.cmdlet()))
}

/// Pass when `key` is `false`.
fn off(
    v: &Value,
    cfg: TeamsConfig,
    key: &str,
    on_text: &str,
    off_text: &str,
    on_status: FindingStatus,
) -> Outcome {
    let on = need_bool(v, cfg, key)?;
    Ok(if on {
        (on_status, on_text.to_string())
    } else {
        (FindingStatus::Pass, off_text.to_string())
    })
}

const FED: TeamsConfig = TeamsConfig::TenantFederationSettings;
const CLIENT: TeamsConfig = TeamsConfig::TeamsClientConfiguration;
const MEETING: TeamsConfig = TeamsConfig::TeamsMeetingPolicy;

// TEAMS-EXTACCESS-001 (8.2.2): communication with unmanaged (personal) Teams accounts disabled.
pub fn extaccess_001(fed: &Value) -> Outcome {
    off(
        fed,
        FED,
        "AllowTeamsConsumer",
        "Unmanaged Teams accounts can communicate with users",
        "Blocked",
        FindingStatus::Fail,
    )
}

// TEAMS-EXTACCESS-002 (8.2.3): unmanaged Teams users cannot start conversations.
pub fn extaccess_002(fed: &Value) -> Outcome {
    if bool_of(fed, "AllowTeamsConsumer") == Some(false) {
        return Ok((
            FindingStatus::Pass,
            "Unmanaged Teams accounts blocked entirely".to_string(),
        ));
    }
    off(
        fed,
        FED,
        "AllowTeamsConsumerInbound",
        "Unmanaged Teams accounts can initiate conversations",
        "Only your users can initiate",
        FindingStatus::Fail,
    )
}

// TEAMS-EXTACCESS-003 (8.2.1): external domains restricted (federation off or an explicit allow list).
pub fn extaccess_003(fed: &Value) -> Outcome {
    let federated = need_bool(fed, FED, "AllowFederatedUsers")?;
    if !federated {
        return Ok((FindingStatus::Pass, "External access disabled".to_string()));
    }
    let blocked = fed
        .get("BlockedDomains")
        .and_then(|b| b.as_array())
        .map(|b| b.len())
        .unwrap_or(0);
    Ok(match AllowedDomains::parse(fed) {
        AllowedDomains::List(list) => (
            FindingStatus::Pass,
            format!("Allow only specific external domains: {} domain(s)", list.len()),
        ),
        AllowedDomains::All if blocked > 0 => (
            FindingStatus::Warning,
            format!("All domains allowed except {blocked} blocked; an allow list is the restrictive option"),
        ),
        AllowedDomains::All => (FindingStatus::Fail, "All external domains allowed".to_string()),
    })
}

// TEAMS-EXTACCESS-004 (8.2.4): communication with Skype (consumer) users disabled.
pub fn extaccess_004(fed: &Value) -> Outcome {
    off(
        fed,
        FED,
        "AllowPublicUsers",
        "Skype users can communicate with users",
        "Blocked",
        FindingStatus::Fail,
    )
}

// TEAMS-MEETING-001 (8.5.1): anonymous users can't join a meeting.
pub fn meeting_001(m: &Value) -> Outcome {
    off(
        m,
        MEETING,
        "AllowAnonymousUsersToJoinMeeting",
        "Anonymous users can join",
        "Anonymous join blocked",
        FindingStatus::Fail,
    )
}

// TEAMS-MEETING-002 (8.5.2): anonymous users and dial-in callers can't start a meeting.
pub fn meeting_002(m: &Value) -> Outcome {
    off(
        m,
        MEETING,
        "AllowAnonymousUsersToStartMeeting",
        "Anonymous users and dial-in callers can start meetings",
        "Blocked",
        FindingStatus::Fail,
    )
}

// TEAMS-MEETING-003 (8.5.3): only people in the organisation bypass the lobby.
pub fn meeting_003(m: &Value) -> Outcome {
    let v = need_str(m, MEETING, "AutoAdmittedUsers")?;
    let status = match v.to_ascii_lowercase().as_str() {
        "everyoneincompany"
        | "everyoneincompanyexcludingguests"
        | "invitedusers"
        | "organizeronly" => FindingStatus::Pass,
        "everyoneinsameandfederatedcompany" => FindingStatus::Warning,
        "everyone" => FindingStatus::Fail,
        _ => FindingStatus::Warning,
    };
    Ok((status, format!("AutoAdmittedUsers: {v}")))
}

// TEAMS-MEETING-004 (8.5.4): dial-in users can't bypass the lobby.
pub fn meeting_004(m: &Value) -> Outcome {
    off(
        m,
        MEETING,
        "AllowPSTNUsersToBypassLobby",
        "Dial-in users bypass the lobby",
        "Dial-in users wait in the lobby",
        FindingStatus::Fail,
    )
}

// TEAMS-MEETING-005 (8.5.7): external participants can't give or request control.
pub fn meeting_005(m: &Value) -> Outcome {
    off(
        m,
        MEETING,
        "AllowExternalParticipantGiveRequestControl",
        "External participants can give or request control",
        "Blocked",
        FindingStatus::Fail,
    )
}

// TEAMS-MEETING-006 (8.5.5): meeting chat excludes anonymous users.
pub fn meeting_006(m: &Value) -> Outcome {
    let v = need_str(m, MEETING, "MeetingChatEnabledType")?;
    let status = match v.to_ascii_lowercase().as_str() {
        "enabledexceptanonymous" | "disabled" => FindingStatus::Pass,
        "enabled" => FindingStatus::Fail,
        _ => FindingStatus::Warning,
    };
    Ok((status, format!("MeetingChatEnabledType: {v}")))
}

// TEAMS-MEETING-007 (8.5.6): only organisers and co-organisers present.
pub fn meeting_007(m: &Value) -> Outcome {
    let v = need_str(m, MEETING, "DesignatedPresenterRoleMode")?;
    let status = match v.to_ascii_lowercase().as_str() {
        "organizeronlyuseroverride" => FindingStatus::Pass,
        "everyoneincompanyuseroverride" => FindingStatus::Warning,
        _ => FindingStatus::Fail,
    };
    Ok((status, format!("DesignatedPresenterRoleMode: {v}")))
}

// TEAMS-MEETING-008 (8.5.8): external meeting chat off.
pub fn meeting_008(m: &Value) -> Outcome {
    off(
        m,
        MEETING,
        "AllowExternalNonTrustedMeetingChat",
        "Chat allowed in meetings hosted by non-trusted organisations",
        "External meeting chat off",
        FindingStatus::Fail,
    )
}

// TEAMS-MEETING-009 (8.5.9): meeting recording off by default.
pub fn meeting_009(m: &Value) -> Outcome {
    off(
        m,
        MEETING,
        "AllowCloudRecording",
        "Cloud recording allowed in the Global policy",
        "Recording off",
        FindingStatus::Fail,
    )
}

const STORAGE_PROVIDERS: [(&str, &str); 5] = [
    ("AllowDropBox", "Dropbox"),
    ("AllowBox", "Box"),
    ("AllowGoogleDrive", "Google Drive"),
    ("AllowShareFile", "ShareFile"),
    ("AllowEgnyte", "Egnyte"),
];

// TEAMS-CLIENT-001 (8.1.1): third-party cloud storage in Teams limited to approved services.
pub fn client_001(c: &Value) -> Outcome {
    let mut enabled = Vec::new();
    let mut seen = 0;
    for (key, name) in STORAGE_PROVIDERS {
        if let Some(on) = bool_of(c, key) {
            seen += 1;
            if on {
                enabled.push(name);
            }
        }
    }
    if seen == 0 {
        anyhow::bail!(
            "{} did not include the cloud storage settings",
            CLIENT.cmdlet()
        );
    }
    Ok(if enabled.is_empty() {
        (
            FindingStatus::Pass,
            "No third-party cloud storage enabled".to_string(),
        )
    } else {
        (
            FindingStatus::Fail,
            format!("Enabled: {}", enabled.join(", ")),
        )
    })
}

// TEAMS-CLIENT-002 (8.1.2): users can't send email to a channel address.
pub fn client_002(c: &Value) -> Outcome {
    off(
        c,
        CLIENT,
        "AllowEmailIntoChannel",
        "Email into channels allowed",
        "Email into channels blocked",
        FindingStatus::Fail,
    )
}

// TEAMS-GUEST-001: guest access to Teams.
pub fn guest_001(c: &Value) -> Outcome {
    off(
        c,
        CLIENT,
        "AllowGuestUser",
        "Guest access enabled; review guest membership and container labels",
        "Guest access disabled",
        FindingStatus::Warning,
    )
}

// TEAMS-APPS-001: chat resource-specific consent (lets users grant apps access to chat data).
pub fn apps_001(s: &Value) -> Outcome {
    let on = bool_of(s, "isChatResourceSpecificConsentEnabled").ok_or_else(|| {
        anyhow::anyhow!("teamsAppSettings did not include isChatResourceSpecificConsentEnabled")
    })?;
    Ok(if on {
        (
            FindingStatus::Warning,
            "Users can consent to apps accessing chat data".to_string(),
        )
    } else {
        (
            FindingStatus::Pass,
            "Chat resource-specific consent disabled".to_string(),
        )
    })
}

// TEAMS-APPS-002 (8.4.1): third-party and custom apps limited to an allow list in the Global policy.
pub fn apps_002(p: &Value) -> Outcome {
    let third = need_str(
        p,
        TeamsConfig::TeamsAppPermissionPolicy,
        "GlobalCatalogAppsType",
    )?;
    let custom = need_str(
        p,
        TeamsConfig::TeamsAppPermissionPolicy,
        "PrivateCatalogAppsType",
    )?;
    let restricted = |t: &str| t.eq_ignore_ascii_case("AllowedAppList");
    let current = format!("Third-party apps: {third}; custom apps: {custom}");
    Ok(match (restricted(third), restricted(custom)) {
        (true, true) => (FindingStatus::Pass, current),
        (false, false) => (FindingStatus::Fail, current),
        _ => (FindingStatus::Warning, current),
    })
}

// TEAMS-APPS-003: custom app upload (sideloading) blocked in the Global setup policy.
pub fn apps_003(p: &Value) -> Outcome {
    off(
        p,
        TeamsConfig::TeamsAppSetupPolicy,
        "AllowSideLoading",
        "Users can upload custom apps",
        "Custom app upload blocked",
        FindingStatus::Fail,
    )
}

// TEAMS-REPORTING-001 (8.6.1): users can report security concerns in Teams.
pub fn reporting_001(m: &Value) -> Outcome {
    let on = need_bool(
        m,
        TeamsConfig::TeamsMessagingPolicy,
        "AllowSecurityEndUserReporting",
    )?;
    Ok(if on {
        (
            FindingStatus::Pass,
            "End-user security reporting enabled".to_string(),
        )
    } else {
        (
            FindingStatus::Fail,
            "End-user security reporting disabled".to_string(),
        )
    })
}

// TEAMS-PRIVATE-001: team ownership and exposure.
pub fn private_001(teams: &[TeamSummary]) -> (FindingStatus, String, Vec<String>) {
    let under_owned: Vec<&TeamSummary> = teams
        .iter()
        .filter(|t| t.owners.is_some_and(|o| o < 2))
        .collect();
    let public: Vec<&TeamSummary> = teams
        .iter()
        .filter(|t| t.visibility.eq_ignore_ascii_case("Public"))
        .collect();
    let with_guests = teams
        .iter()
        .filter(|t| t.guests.is_some_and(|g| g > 0))
        .count();
    let unresolved = teams.iter().filter(|t| t.owners.is_none()).count();
    let mut summary = format!(
        "{} teams: {} public, {} with fewer than 2 owners, {} with guests",
        teams.len(),
        public.len(),
        under_owned.len(),
        with_guests
    );
    if unresolved > 0 {
        summary.push_str(&format!(" ({unresolved} not inspected)"));
    }
    let names = |list: &[&TeamSummary]| {
        list.iter()
            .map(|t| t.display_name.clone())
            .collect::<Vec<_>>()
    };
    if !under_owned.is_empty() {
        return (FindingStatus::Fail, summary, names(&under_owned));
    }
    if !public.is_empty() {
        return (FindingStatus::Warning, summary, names(&public));
    }
    (FindingStatus::Pass, summary, vec![])
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

pub fn evaluate(d: &TeamsData, registry: &ControlRegistry) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ext = "Teams External Access";
    let meet = "Teams Meetings";
    let client = "Teams Client";
    let apps = "Teams Apps";

    let checks: Vec<(Check, Outcome)> = vec![
        (
            Check { id: "TEAMS-EXTACCESS-001", section: ext, setting: "Unmanaged Teams accounts", description: "Communication with unmanaged (personal) Teams accounts is disabled", expected: "AllowTeamsConsumer: false", remediation: "Turn off 'People in my organization can communicate with Teams users whose accounts aren't managed by an organization' under Teams admin center > Users > External access." },
            ok(&d.federation).and_then(extaccess_001),
        ),
        (
            Check { id: "TEAMS-EXTACCESS-002", section: ext, setting: "Unmanaged accounts initiating chat", description: "Unmanaged Teams users cannot initiate conversations", expected: "AllowTeamsConsumerInbound: false", remediation: "Clear 'External users with Teams accounts not managed by an organization can contact users in my organization' under Teams admin center > Users > External access." },
            ok(&d.federation).and_then(extaccess_002),
        ),
        (
            Check { id: "TEAMS-EXTACCESS-003", section: ext, setting: "External domains", description: "External access is off or allows only specific partner domains", expected: "Allow only specific external domains, or block all", remediation: "Switch to 'Allow only specific external domains' and list approved partners under Teams admin center > Users > External access." },
            ok(&d.federation).and_then(extaccess_003),
        ),
        (
            Check { id: "TEAMS-EXTACCESS-004", section: ext, setting: "Skype users", description: "Communication with Skype (consumer) users is disabled", expected: "AllowPublicUsers: false", remediation: "Turn off 'Allow users in my organization to communicate with Skype users' under Teams admin center > Users > External access." },
            ok(&d.federation).and_then(extaccess_004),
        ),
        (
            Check { id: "TEAMS-MEETING-001", section: meet, setting: "Anonymous join", description: "Anonymous users can't join a meeting", expected: "AllowAnonymousUsersToJoinMeeting: false", remediation: "In the Global meeting policy, set 'Anonymous users can join a meeting' to Off." },
            ok(&d.meeting).and_then(meeting_001),
        ),
        (
            Check { id: "TEAMS-MEETING-002", section: meet, setting: "Anonymous start", description: "Anonymous users and dial-in callers can't start a meeting", expected: "AllowAnonymousUsersToStartMeeting: false", remediation: "In the Global meeting policy, set 'Anonymous users and dial-in callers can start a meeting' to Off." },
            ok(&d.meeting).and_then(meeting_002),
        ),
        (
            Check { id: "TEAMS-MEETING-003", section: meet, setting: "Lobby bypass", description: "Only people in the organisation bypass the lobby", expected: "AutoAdmittedUsers: EveryoneInCompany or stricter", remediation: "In the Global meeting policy, set 'Who can bypass the lobby' to 'People in my org' or stricter." },
            ok(&d.meeting).and_then(meeting_003),
        ),
        (
            Check { id: "TEAMS-MEETING-004", section: meet, setting: "Dial-in lobby bypass", description: "Users dialing in can't bypass the lobby", expected: "AllowPSTNUsersToBypassLobby: false", remediation: "In the Global meeting policy, set 'People dialing in can bypass the lobby' to Off." },
            ok(&d.meeting).and_then(meeting_004),
        ),
        (
            Check { id: "TEAMS-MEETING-005", section: meet, setting: "External control", description: "External participants can't give or request control", expected: "AllowExternalParticipantGiveRequestControl: false", remediation: "In the Global meeting policy, set 'External participants can give or request control' to Off." },
            ok(&d.meeting).and_then(meeting_005),
        ),
        (
            Check { id: "TEAMS-MEETING-006", section: meet, setting: "Anonymous meeting chat", description: "Meeting chat does not allow anonymous users", expected: "MeetingChatEnabledType: EnabledExceptAnonymous", remediation: "In the Global meeting policy, set 'Meeting chat' to 'On for everyone but anonymous users'." },
            ok(&d.meeting).and_then(meeting_006),
        ),
        (
            Check { id: "TEAMS-MEETING-007", section: meet, setting: "Presenter role", description: "Only organisers and co-organisers can present", expected: "DesignatedPresenterRoleMode: OrganizerOnlyUserOverride", remediation: "In the Global meeting policy, set 'Who can present' to 'Only organizers and co-organizers'." },
            ok(&d.meeting).and_then(meeting_007),
        ),
        (
            Check { id: "TEAMS-MEETING-008", section: meet, setting: "External meeting chat", description: "External meeting chat is off", expected: "AllowExternalNonTrustedMeetingChat: false", remediation: "In the Global meeting policy, set 'External meeting chat' to Off." },
            ok(&d.meeting).and_then(meeting_008),
        ),
        (
            Check { id: "TEAMS-MEETING-009", section: meet, setting: "Cloud recording", description: "Meeting recording is off by default", expected: "AllowCloudRecording: false in the Global policy", remediation: "In the Global meeting policy, set 'Meeting recording' to Off and grant recording through a scoped policy where needed." },
            ok(&d.meeting).and_then(meeting_009),
        ),
        (
            Check { id: "TEAMS-CLIENT-001", section: client, setting: "Third-party cloud storage", description: "External file sharing in Teams is limited to approved cloud storage services", expected: "Dropbox, Box, Google Drive, ShareFile and Egnyte off", remediation: "Turn off unapproved third-party storage under Teams admin center > Teams > Teams settings > Files." },
            ok(&d.client).and_then(client_001),
        ),
        (
            Check { id: "TEAMS-CLIENT-002", section: client, setting: "Email into channels", description: "Users can't send emails to a channel email address", expected: "AllowEmailIntoChannel: false", remediation: "Turn off 'Users can send emails to a channel email address' under Teams admin center > Teams > Teams settings > Email integration." },
            ok(&d.client).and_then(client_002),
        ),
        (
            Check { id: "TEAMS-GUEST-001", section: ext, setting: "Guest access", description: "Whether guests can be added to teams", expected: "Guest access off, or on with container labels and periodic membership review", remediation: "Review Teams admin center > Users > Guest access; where guests are needed, govern them with sensitivity labels and access reviews." },
            ok(&d.client).and_then(guest_001),
        ),
        (
            Check { id: "TEAMS-APPS-001", section: apps, setting: "Chat resource-specific consent", description: "Users cannot grant apps resource-specific consent to chat data", expected: "isChatResourceSpecificConsentEnabled: false", remediation: "Disable chat resource-specific consent under Teams admin center > Teams apps > Manage apps > Org-wide app settings (or via Graph teamsAppSettings)." },
            ok(&d.app_settings).and_then(apps_001),
        ),
        (
            Check { id: "TEAMS-APPS-002", section: apps, setting: "App permission policy", description: "Third-party and custom apps are limited to an allow list", expected: "GlobalCatalogAppsType and PrivateCatalogAppsType: AllowedAppList", remediation: "In the Global app permission policy (or app-centric management), block third-party and custom apps by default and allow approved apps individually." },
            ok(&d.app_permission).and_then(apps_002),
        ),
        (
            Check { id: "TEAMS-APPS-003", section: apps, setting: "Custom app upload", description: "Users cannot upload custom apps", expected: "AllowSideLoading: false in the Global setup policy", remediation: "In the Global app setup policy, turn off 'Upload custom apps' and grant it to developers through a scoped policy." },
            ok(&d.app_setup).and_then(apps_003),
        ),
        (
            Check { id: "TEAMS-REPORTING-001", section: client, setting: "Security reporting", description: "Users can report security concerns in Teams", expected: "AllowSecurityEndUserReporting: true", remediation: "In the Global messaging policy, turn on 'Report a security concern', and enable user-reported messages for Teams in Defender." },
            ok(&d.messaging).and_then(reporting_001),
        ),
    ];
    for (check, outcome) in checks {
        emit(&mut findings, registry, &check, outcome);
    }

    // TEAMS-PRIVATE-001 and TEAMS-INFO-001 come from the team inventory.
    let section = "Teams Inventory";
    match &d.teams {
        Ok(teams) => {
            let (status, current, affected) = private_001(teams);
            let mut f = Finding::new(
                "TEAMS-PRIVATE-001",
                CATEGORY,
                section,
                "Team ownership and exposure",
                "Every team has at least two owners; public teams and teams with guests are listed for review",
            )
            .status(status)
            .severity(registry.get_severity("TEAMS-PRIVATE-001"))
            .current_value(current)
            .expected_value("No team with fewer than 2 owners; crown-jewel teams private and guest-free")
            .remediation(
                "Add a second owner to under-owned teams, make sensitive teams private, and apply a container sensitivity label that blocks guests.",
            );
            if !affected.is_empty() {
                f = f.affected_resources(affected);
            }
            findings.push(f.build());
            findings.push(
                Finding::new(
                    "TEAMS-INFO-001",
                    CATEGORY,
                    section,
                    "Teams workload",
                    "Teams workload is in use",
                )
                .status(FindingStatus::Info)
                .severity(registry.get_severity("TEAMS-INFO-001"))
                .current_value(format!("{} teams", teams.len()))
                .expected_value("Informational")
                .remediation("Apply the TEAMS-* controls above to the tenant.")
                .build(),
            );
        }
        Err(e) => {
            findings.push(Finding::unknown(
                "TEAMS-PRIVATE-001",
                CATEGORY,
                section,
                "Team ownership and exposure",
                "Every team has at least two owners; public teams and teams with guests are listed for review",
                e,
            ));
            findings.push(Finding::unknown(
                "TEAMS-INFO-001",
                CATEGORY,
                section,
                "Teams workload",
                "Teams workload is in use",
                e,
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hardened() -> TeamsData {
        TeamsData {
            federation: Ok(json!({
                "Identity": "Global", "AllowFederatedUsers": true, "AllowTeamsConsumer": false,
                "AllowTeamsConsumerInbound": false, "AllowPublicUsers": false,
                "AllowedDomains": {"AllowedDomain": [{"Domain": "contoso.com"}]}, "BlockedDomains": []
            })),
            client: Ok(json!({
                "Identity": "Global", "AllowEmailIntoChannel": false, "AllowDropBox": false, "AllowBox": false,
                "AllowGoogleDrive": false, "AllowShareFile": false, "AllowEgnyte": false, "AllowGuestUser": false
            })),
            meeting: Ok(json!({
                "Identity": "Global", "AllowAnonymousUsersToJoinMeeting": false, "AllowAnonymousUsersToStartMeeting": false,
                "AutoAdmittedUsers": "EveryoneInCompanyExcludingGuests", "AllowPSTNUsersToBypassLobby": false,
                "AllowExternalParticipantGiveRequestControl": false, "MeetingChatEnabledType": "EnabledExceptAnonymous",
                "DesignatedPresenterRoleMode": "OrganizerOnlyUserOverride", "AllowExternalNonTrustedMeetingChat": false,
                "AllowCloudRecording": false
            })),
            app_permission: Ok(
                json!({"Identity": "Global", "DefaultCatalogAppsType": "BlockedAppList", "GlobalCatalogAppsType": "AllowedAppList", "PrivateCatalogAppsType": "AllowedAppList"}),
            ),
            app_setup: Ok(json!({"Identity": "Global", "AllowSideLoading": false})),
            messaging: Ok(json!({"Identity": "Global", "AllowSecurityEndUserReporting": true})),
            app_settings: Ok(json!({"isChatResourceSpecificConsentEnabled": false})),
            teams: Ok(vec![TeamSummary {
                id: "1".into(),
                display_name: "Board".into(),
                visibility: "Private".into(),
                owners: Some(2),
                guests: Some(0),
            }]),
            raw: Value::Null,
        }
    }

    fn registry() -> ControlRegistry {
        ControlRegistry::load(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("controls")
                .as_path(),
        )
        .unwrap()
    }

    #[test]
    fn hardened_tenant_passes_every_check() {
        let findings = evaluate(&hardened(), &registry());
        let non_pass: Vec<_> = findings
            .iter()
            .filter(|f| !matches!(f.status, FindingStatus::Pass | FindingStatus::Info))
            .map(|f| format!("{} {}", f.check_id, f.current_value))
            .collect();
        assert!(non_pass.is_empty(), "{non_pass:?}");
        assert_eq!(findings.len(), 22);
    }

    #[test]
    fn ids_test_their_registry_setting() {
        let fed = json!({"AllowFederatedUsers": true, "AllowTeamsConsumer": true, "AllowTeamsConsumerInbound": true, "AllowPublicUsers": true, "AllowedDomains": {"AllowAllKnownDomains": {}}});
        assert_eq!(extaccess_001(&fed).unwrap().0, FindingStatus::Fail);
        assert_eq!(extaccess_002(&fed).unwrap().0, FindingStatus::Fail);
        assert_eq!(extaccess_003(&fed).unwrap().0, FindingStatus::Fail);
        assert_eq!(extaccess_004(&fed).unwrap().0, FindingStatus::Fail);
        let fed_blocklist =
            json!({"AllowFederatedUsers": true, "BlockedDomains": [{"Domain": "evil.com"}]});
        assert_eq!(
            extaccess_003(&fed_blocklist).unwrap().0,
            FindingStatus::Warning
        );
        let fed_off = json!({"AllowFederatedUsers": false});
        assert_eq!(extaccess_003(&fed_off).unwrap().0, FindingStatus::Pass);

        let lax = json!({
            "AllowAnonymousUsersToJoinMeeting": true, "AllowAnonymousUsersToStartMeeting": true,
            "AutoAdmittedUsers": "Everyone", "AllowPSTNUsersToBypassLobby": true,
            "AllowExternalParticipantGiveRequestControl": true, "MeetingChatEnabledType": "Enabled",
            "DesignatedPresenterRoleMode": "EveryoneUserOverride", "AllowExternalNonTrustedMeetingChat": true,
            "AllowCloudRecording": true
        });
        for f in [
            meeting_001,
            meeting_002,
            meeting_003,
            meeting_004,
            meeting_005,
            meeting_006,
            meeting_007,
            meeting_008,
            meeting_009,
        ] {
            assert_eq!(f(&lax).unwrap().0, FindingStatus::Fail);
        }
        assert_eq!(
            meeting_003(&json!({"AutoAdmittedUsers": "EveryoneInSameAndFederatedCompany"}))
                .unwrap()
                .0,
            FindingStatus::Warning
        );

        let client = json!({"AllowEmailIntoChannel": "True", "AllowDropBox": true, "AllowBox": false, "AllowGuestUser": true});
        assert_eq!(
            client_001(&client).unwrap(),
            (FindingStatus::Fail, "Enabled: Dropbox".to_string())
        );
        assert_eq!(client_002(&client).unwrap().0, FindingStatus::Fail);
        assert_eq!(guest_001(&client).unwrap().0, FindingStatus::Warning);

        assert_eq!(
            apps_002(&json!({"GlobalCatalogAppsType": "BlockedAppList", "PrivateCatalogAppsType": "AllowedAppList"})).unwrap().0,
            FindingStatus::Warning
        );
        assert_eq!(
            apps_003(&json!({"AllowSideLoading": true})).unwrap().0,
            FindingStatus::Fail
        );
        assert_eq!(
            apps_001(&json!({"isChatResourceSpecificConsentEnabled": true}))
                .unwrap()
                .0,
            FindingStatus::Warning
        );
        assert_eq!(
            reporting_001(&json!({"AllowSecurityEndUserReporting": false}))
                .unwrap()
                .0,
            FindingStatus::Fail
        );
    }

    #[test]
    fn missing_field_is_an_error_not_review() {
        let err = meeting_009(&json!({"Identity": "Global"}))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Get-CsTeamsMeetingPolicy") && err.contains("AllowCloudRecording"),
            "{err}"
        );
        assert!(client_001(&json!({})).is_err());
    }

    #[test]
    fn api_refusal_becomes_unknown_for_every_dependent_check() {
        let mut d = hardened();
        d.meeting = Err(anyhow::anyhow!(
            "Teams admin (Skype.Policy) error 403 Forbidden for .../TeamsMeetingPolicy"
        ));
        let findings = evaluate(&d, &registry());
        let meeting: Vec<_> = findings
            .iter()
            .filter(|f| f.check_id.starts_with("TEAMS-MEETING-"))
            .collect();
        assert_eq!(meeting.len(), 9);
        assert!(meeting
            .iter()
            .all(|f| f.status == FindingStatus::Unknown && f.current_value.contains("Forbidden")));
        assert!(!findings.iter().any(|f| f.status == FindingStatus::Review));
    }

    #[test]
    fn team_inventory_outcomes() {
        let mk = |name: &str, vis: &str, owners: usize, guests: usize| TeamSummary {
            id: name.into(),
            display_name: name.into(),
            visibility: vis.into(),
            owners: Some(owners),
            guests: Some(guests),
        };
        let (s, _, affected) = private_001(&[mk("A", "Private", 2, 0), mk("B", "Public", 2, 1)]);
        assert_eq!(s, FindingStatus::Warning);
        assert_eq!(affected, vec!["B"]);
        let (s, text, affected) = private_001(&[mk("A", "Private", 1, 0), mk("B", "Public", 2, 1)]);
        assert_eq!(s, FindingStatus::Fail);
        assert_eq!(affected, vec!["A"]);
        assert!(text.contains("1 with guests"), "{text}");
        let (s, _, _) = private_001(&[mk("A", "Private", 3, 0)]);
        assert_eq!(s, FindingStatus::Pass);
    }
}
