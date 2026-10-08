//! Tenant-wide identity settings: authentication methods policy, Security Defaults, SSPR, guest
//! and cross-tenant access, device registration, domains/hybrid auth, per-user MFA.

use anyhow::Result;
use serde_json::Value;

use super::{Ctx, Meta};
use crate::assessment::finding::{Finding, FindingStatus};

const MAX_PER_USER_MFA_CALLS: usize = 200;
const GUEST_ROLE_RESTRICTED: &str = "2af84b1e-32c8-42b7-82bc-daa82404023b";
const GUEST_ROLE_LIMITED: &str = "a0b1b346-4d3e-4e8b-98f8-753987be4970";
const GUEST_ROLE_MEMBER: &str = "10dae51f-b6af-4016-8d66-8c2a99b929b3";

// ---------------------------------------------------------------------------
// Authentication methods policy
// ---------------------------------------------------------------------------

pub const ENTRA_AUTHMETHOD_001: Meta = Meta {
    id: "ENTRA-AUTHMETHOD-001",
    section: "Authentication Methods",
    setting: "SMS and voice call disabled",
    description: "The SMS and Voice call authentication methods are disabled in the Authentication methods policy",
};
pub const ENTRA_AUTHMETHOD_002: Meta = Meta {
    id: "ENTRA-AUTHMETHOD-002",
    section: "Authentication Methods",
    setting: "Email OTP disabled",
    description: "The Email OTP authentication method is disabled (or not targeted at members)",
};
pub const ENTRA_AUTHMETHOD_003: Meta = Meta {
    id: "ENTRA-AUTHMETHOD-003",
    section: "Authentication Methods",
    setting: "Microsoft Authenticator MFA-fatigue protection",
    description: "Microsoft Authenticator is enabled with application name and geographic location shown in push notifications (number matching is enforced by Microsoft)",
};
pub const ENTRA_AUTHMETHOD_004: Meta = Meta {
    id: "ENTRA-AUTHMETHOD-004",
    section: "Authentication Methods",
    setting: "System-preferred MFA",
    description: "System-preferred multifactor authentication is enabled",
};
pub const ENTRA_AUTHMETHOD_005: Meta = Meta {
    id: "ENTRA-AUTHMETHOD-005",
    section: "Authentication Methods",
    setting: "Authentication methods policy migration",
    description: "Legacy MFA and SSPR policies have been migrated to the Authentication methods policy (policyMigrationState = migrationComplete)",
};

/// How a method configuration is targeted: (state, targets everyone, target summary).
pub fn method_targeting(cfg: &Value) -> (String, bool, String) {
    let state = cfg["state"].as_str().unwrap_or("unknown").to_string();
    let targets: Vec<&str> = cfg["includeTargets"]
        .as_array()
        .map(|a| a.iter().filter_map(|t| t["id"].as_str()).collect())
        .unwrap_or_default();
    let all = targets.iter().any(|t| t.eq_ignore_ascii_case("all_users"));
    let summary = if targets.is_empty() {
        "no targets".to_string()
    } else if all {
        "all users".to_string()
    } else {
        format!("{} group(s)", targets.len())
    };
    (state, all, summary)
}

fn method_config<'a>(policy: &'a Value, id: &str) -> Option<&'a Value> {
    policy["authenticationMethodConfigurations"]
        .as_array()?
        .iter()
        .find(|c| c["id"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(id)))
}

/// Pass when disabled, Warning when enabled for specific groups only, Fail when enabled for everyone.
fn weak_method_status(cfg: Option<&Value>) -> (FindingStatus, String) {
    let Some(cfg) = cfg else {
        return (FindingStatus::Pass, "not present (disabled)".into());
    };
    let (state, all, summary) = method_targeting(cfg);
    if state != "enabled" {
        (FindingStatus::Pass, state.to_string())
    } else if all {
        (FindingStatus::Fail, format!("enabled for {summary}"))
    } else {
        (FindingStatus::Warning, format!("enabled for {summary}"))
    }
}

fn worst(a: FindingStatus, b: FindingStatus) -> FindingStatus {
    let rank = |s: FindingStatus| match s {
        FindingStatus::Fail => 3,
        FindingStatus::Warning => 2,
        FindingStatus::Pass => 0,
        _ => 1,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

pub fn check_auth_methods(ctx: &Ctx, policy: &Result<Value>) -> Vec<Result<Finding>> {
    let policy = match policy {
        Ok(p) => p,
        Err(e) => {
            return (0..5)
                .map(|_| {
                    Err(anyhow::anyhow!(
                        "authenticationMethodsPolicy unreadable: {e}"
                    ))
                })
                .collect()
        }
    };
    let mut out = Vec::new();

    let (sms_status, sms) = weak_method_status(method_config(policy, "Sms"));
    let (voice_status, voice) = weak_method_status(method_config(policy, "Voice"));
    out.push(Ok(ctx
        .finding(&ENTRA_AUTHMETHOD_001)
        .status(worst(sms_status, voice_status))
        .current_value(format!("SMS: {sms}; Voice: {voice}"))
        .expected_value("Authentication methods policy: SMS = Disabled, Voice call = Disabled")
        .remediation("Entra admin center > Protection > Authentication methods > Policies: set SMS and Voice call to Disabled (after users register Authenticator or passkeys).")
        .build()));

    let (email_status, email) = weak_method_status(method_config(policy, "Email"));
    out.push(Ok(ctx
        .finding(&ENTRA_AUTHMETHOD_002)
        .status(email_status)
        .current_value(format!("Email OTP: {email}"))
        .expected_value("Authentication methods policy: Email OTP = Disabled")
        .remediation("Entra admin center > Protection > Authentication methods > Policies > Email OTP: Disabled.")
        .build()));

    let auth = method_config(policy, "MicrosoftAuthenticator");
    let (status, current) = match auth {
        Some(cfg) if cfg["state"].as_str() == Some("enabled") => {
            let fs = &cfg["featureSettings"];
            let app = fs["displayAppInformationRequiredState"]["state"]
                .as_str()
                .unwrap_or("default");
            let loc = fs["displayLocationInformationRequiredState"]["state"]
                .as_str()
                .unwrap_or("default");
            let on = |s: &str| s == "enabled";
            let status = if on(app) && on(loc) {
                FindingStatus::Pass
            } else if on(app) || on(loc) {
                FindingStatus::Warning
            } else {
                FindingStatus::Fail
            };
            (
                status,
                format!("Authenticator enabled; application context = {app}, location context = {loc}; number matching enforced by Microsoft"),
            )
        }
        Some(_) => (
            FindingStatus::Fail,
            "Microsoft Authenticator method is disabled".into(),
        ),
        None => (
            FindingStatus::Fail,
            "Microsoft Authenticator configuration not present".into(),
        ),
    };
    out.push(Ok(ctx
        .finding(&ENTRA_AUTHMETHOD_003)
        .status(status)
        .current_value(current)
        .expected_value("MicrosoftAuthenticator enabled; featureSettings.displayAppInformationRequiredState and displayLocationInformationRequiredState = enabled for all users")
        .remediation("Authentication methods > Microsoft Authenticator > Configure: 'Show application name' and 'Show geographic location' = Enabled, target All users.")
        .build()));

    let spm = policy["systemCredentialPreferences"]["state"]
        .as_str()
        .unwrap_or("default");
    out.push(Ok(ctx
        .finding(&ENTRA_AUTHMETHOD_004)
        .status(match spm {
            "enabled" => FindingStatus::Pass,
            "disabled" => FindingStatus::Fail,
            _ => FindingStatus::Warning,
        })
        .current_value(format!("systemCredentialPreferences.state = {spm}"))
        .expected_value("System-preferred multifactor authentication = Enabled (explicit, not Microsoft managed)")
        .remediation("Authentication methods > Settings > System-preferred multifactor authentication: Enabled, target All users.")
        .build()));

    let mig = policy["policyMigrationState"].as_str().unwrap_or("unknown");
    out.push(Ok(ctx
        .finding(&ENTRA_AUTHMETHOD_005)
        .status(match mig {
            "migrationComplete" => FindingStatus::Pass,
            "migrationInProgress" => FindingStatus::Warning,
            _ => FindingStatus::Fail,
        })
        .current_value(format!("policyMigrationState = {mig}"))
        .expected_value("policyMigrationState = migrationComplete")
        .remediation("Authentication methods > Policies > 'Manage migration': move legacy MFA and SSPR method settings into the policy, then mark migration complete.")
        .build()));
    out
}

pub const ENTRA_PASSWORD_001: Meta = Meta {
    id: "ENTRA-PASSWORD-001",
    section: "Authentication Methods",
    setting: "Passwordless method enabled",
    description: "At least one passwordless method (FIDO2/passkeys, Microsoft Authenticator, Windows Hello for Business) is enabled",
};

pub fn check_passwordless_enabled(ctx: &Ctx, policy: &Result<Value>) -> Result<Finding> {
    let policy = policy.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
    let enabled: Vec<String> = policy["authenticationMethodConfigurations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["state"].as_str() == Some("enabled"))
        .filter_map(|c| c["id"].as_str().map(String::from))
        .collect();
    let passwordless: Vec<&String> = enabled
        .iter()
        .filter(|id| {
            matches!(
                id.as_str(),
                "Fido2" | "MicrosoftAuthenticator" | "WindowsHelloForBusiness"
            )
        })
        .collect();
    Ok(ctx
        .finding(&ENTRA_PASSWORD_001)
        .status(if passwordless.is_empty() {
            FindingStatus::Fail
        } else {
            FindingStatus::Pass
        })
        .current_value(format!("Enabled methods: {}", enabled.join(", ")))
        .expected_value("Fido2 (passkeys) enabled; Microsoft Authenticator enabled")
        .remediation("Authentication methods > Policies: enable Passkey (FIDO2) and Microsoft Authenticator for all users.")
        .build())
}

// ---------------------------------------------------------------------------
// Password protection / SSPR / Security Defaults / MFA registration
// ---------------------------------------------------------------------------

pub const ENTRA_PASSWORD_002: Meta = Meta {
    id: "ENTRA-PASSWORD-002",
    section: "Password Management",
    setting: "Custom banned password list",
    description: "Entra password protection has a custom banned password list enabled",
};

pub async fn check_banned_passwords(ctx: &Ctx<'_>) -> Result<Finding> {
    let settings: Vec<Value> = ctx.graph.get_all("/v1.0/groupSettings").await?;
    let rules = settings
        .iter()
        .find(|s| s["displayName"].as_str() == Some("Password Rule Settings"));
    let value = |name: &str| -> Option<String> {
        rules?["values"]
            .as_array()?
            .iter()
            .find(|v| v["name"].as_str() == Some(name))
            .and_then(|v| v["value"].as_str().map(String::from))
    };
    let enabled =
        value("EnableBannedPasswordCheck").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let count = value("BannedPasswordList")
        .map(|l| l.split('\t').filter(|x| !x.trim().is_empty()).count())
        .unwrap_or(0);
    let status = if rules.is_none() {
        FindingStatus::Fail
    } else if enabled && count > 0 {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };
    Ok(ctx
        .finding(&ENTRA_PASSWORD_002)
        .status(status)
        .current_value(if rules.is_none() {
            "'Password Rule Settings' not configured (defaults: no custom list)".to_string()
        } else {
            format!("EnableBannedPasswordCheck = {enabled}; {count} custom banned term(s)")
        })
        .expected_value("Password Rule Settings: EnableBannedPasswordCheck = true with a populated BannedPasswordList")
        .remediation("Entra admin center > Protection > Authentication methods > Password protection: 'Enforce custom list' = Yes and add organisation-specific terms.")
        .build())
}

pub const ENTRA_SSPR_001: Meta = Meta {
    id: "ENTRA-SSPR-001",
    section: "Password Management",
    setting: "Self-service password reset",
    description: "Self-service password reset is enabled for users",
};

pub fn check_sspr(ctx: &Ctx) -> Result<Finding> {
    let policy = ctx.authz()?;
    let sspr = policy["allowedToUseSSPR"].as_bool();
    Ok(ctx
        .finding(&ENTRA_SSPR_001)
        .status(match sspr {
            Some(true) => FindingStatus::Pass,
            Some(false) => FindingStatus::Fail,
            None => FindingStatus::Warning,
        })
        .current_value(format!(
            "allowedToUseSSPR = {}",
            sspr.map(|b| b.to_string()).unwrap_or("not returned".into())
        ))
        .expected_value("authorizationPolicy.allowedToUseSSPR = true")
        .remediation("Entra admin center > Protection > Password reset > Properties: Self service password reset enabled = All.")
        .build())
}

pub const ENTRA_SECDEFAULT_001: Meta = Meta {
    id: "ENTRA-SECDEFAULT-001",
    section: "Security Defaults",
    setting: "Security Defaults or Conditional Access MFA",
    description: "Security Defaults are enabled, or an enabled Conditional Access policy requires MFA for All users",
};

pub fn check_security_defaults(ctx: &Ctx) -> Result<Finding> {
    let enabled = ctx.security_defaults()?;
    let ca_mfa_all = ctx
        .enabled_ca()
        .map(|p| {
            p.iter()
                .any(|p| super::ca::targets_all_users(p) && super::ca::requires_mfa(p))
        })
        .unwrap_or(false);
    let (status, current) = if enabled {
        (FindingStatus::Pass, "Security Defaults enabled".to_string())
    } else if ca_mfa_all {
        (
            FindingStatus::Pass,
            "Security Defaults disabled; Conditional Access requires MFA for All users".to_string(),
        )
    } else {
        (
            FindingStatus::Fail,
            "Security Defaults disabled and no enabled Conditional Access policy requires MFA for All users".to_string(),
        )
    };
    Ok(ctx
        .finding(&ENTRA_SECDEFAULT_001)
        .status(status)
        .current_value(current)
        .expected_value("identitySecurityDefaultsEnforcementPolicy.isEnabled = true, or an all-users MFA Conditional Access policy")
        .remediation("Without Entra ID P1: Entra admin center > Identity > Overview > Properties > Manage security defaults = Enabled. With P1: build the all-users MFA policy and keep Security Defaults off.")
        .build())
}

pub const ENTRA_MFA_001: Meta = Meta {
    id: "ENTRA-MFA-001",
    section: "Multi-Factor Authentication",
    setting: "MFA registration",
    description: "Users are registered for MFA (userRegistrationDetails.isMfaRegistered)",
};

pub async fn check_mfa_registration(ctx: &Ctx<'_>) -> Result<Finding> {
    let details: Vec<Value> = ctx
        .graph
        .get_all("/v1.0/reports/authenticationMethods/userRegistrationDetails")
        .await?;
    let members: Vec<&Value> = details
        .iter()
        .filter(|d| {
            d["userType"]
                .as_str()
                .is_none_or(|t| t.eq_ignore_ascii_case("member"))
        })
        .collect();
    let total = members.len();
    let registered = members
        .iter()
        .filter(|d| d["isMfaRegistered"].as_bool().unwrap_or(false))
        .count();
    let pct = if total > 0 {
        registered as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    let threshold = if total <= 5 { 80.0 } else { 90.0 };
    let status = if total > 0 && registered == total {
        FindingStatus::Pass
    } else if pct >= threshold {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };
    let unregistered: Vec<String> = members
        .iter()
        .filter(|d| !d["isMfaRegistered"].as_bool().unwrap_or(false))
        .filter_map(|d| d["userPrincipalName"].as_str().map(String::from))
        .take(50)
        .collect();
    Ok(ctx
        .finding(&ENTRA_MFA_001)
        .status(status)
        .current_value(format!("{registered}/{total} member users MFA-registered ({pct:.1}%)"))
        .expected_value("100% of member users registered for MFA")
        .remediation("Use a registration campaign (Authentication methods > Registration campaign) and the all-users MFA policy to drive registration; disable or remove unregistered stale accounts.")
        .affected_resources(unregistered)
        .build())
}

pub const ENTRA_PERUSER_001: Meta = Meta {
    id: "ENTRA-PERUSER-001",
    section: "Multi-Factor Authentication",
    setting: "Legacy per-user MFA",
    description: "No member user has legacy per-user MFA enabled or enforced (MFA comes from Conditional Access)",
};

pub async fn check_per_user_mfa(ctx: &Ctx<'_>) -> Result<Finding> {
    let users: Vec<Value> = ctx
        .graph
        .get_all("/v1.0/users?$select=id,userPrincipalName,userType,accountEnabled&$top=999")
        .await?;
    let mut candidates: Vec<&Value> = users
        .iter()
        .filter(|u| {
            u["accountEnabled"].as_bool().unwrap_or(true)
                && u["userType"]
                    .as_str()
                    .is_none_or(|t| t.eq_ignore_ascii_case("member"))
        })
        .collect();
    // Privileged users first so the sample is the one that matters most.
    if let Ok(priv_) = ctx.privileged() {
        let ids: std::collections::BTreeSet<&str> = priv_.users().map(|m| m.id.as_str()).collect();
        candidates.sort_by_key(|u| !ids.contains(u["id"].as_str().unwrap_or("")));
    }
    let total = candidates.len();
    let sample: Vec<&Value> = candidates
        .into_iter()
        .take(MAX_PER_USER_MFA_CALLS)
        .collect();
    let mut legacy: Vec<String> = Vec::new();
    for (i, u) in sample.iter().enumerate() {
        let id = u["id"].as_str().unwrap_or_default();
        let req = ctx
            .graph
            .get_json(&format!("/beta/users/{id}/authentication/requirements"))
            .await;
        let req = match req {
            Ok(r) => r,
            Err(e) if i == 0 => return Err(e),
            Err(_) => continue,
        };
        let state = req["perUserMfaState"].as_str().unwrap_or("disabled");
        if state != "disabled" {
            legacy.push(format!(
                "{} ({state})",
                u["userPrincipalName"].as_str().unwrap_or(id)
            ));
        }
    }
    let sampled = sample.len() < total;
    let status = if !legacy.is_empty() {
        FindingStatus::Fail
    } else if sampled {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    Ok(ctx
        .finding(&ENTRA_PERUSER_001)
        .status(status)
        .current_value(format!(
            "{} of {} checked users have per-user MFA enabled/enforced{}",
            legacy.len(),
            sample.len(),
            if sampled { format!(" (sampled; {total} members in total)") } else { String::new() }
        ))
        .expected_value("perUserMfaState = disabled for every member")
        .remediation("Entra admin center > Users > Per-user MFA: set every user to Disabled once the Conditional Access MFA policy is enforced (or use the migration wizard in Authentication methods).")
        .affected_resources(legacy)
        .build())
}

pub const ENTRA_LINKEDIN_001: Meta = Meta {
    id: "ENTRA-LINKEDIN-001",
    section: "External Integrations",
    setting: "LinkedIn account connections",
    description: "LinkedIn account connections are disabled for users",
};

pub fn check_linkedin(ctx: &Ctx) -> Finding {
    ctx.finding(&ENTRA_LINKEDIN_001)
        .status(FindingStatus::Review)
        .current_value("Not readable through Microsoft Graph; verify in the portal")
        .expected_value("Entra admin center > Users > User settings > LinkedIn account connections = No")
        .remediation("Entra admin center > Identity > Users > User settings: set 'Allow users to connect their work or school account with LinkedIn' to No.")
        .build()
}

// ---------------------------------------------------------------------------
// Guests and cross-tenant access
// ---------------------------------------------------------------------------

pub const ENTRA_GUEST_001: Meta = Meta {
    id: "ENTRA-GUEST-001",
    section: "Guest Access",
    setting: "Guest user access restrictions",
    description: "Guest users have the most restricted directory access (restricted guest role)",
};
pub const ENTRA_GUEST_002: Meta = Meta {
    id: "ENTRA-GUEST-002",
    section: "Guest Access",
    setting: "Guest invitation permissions",
    description: "Only admins and users in the Guest Inviter role can invite guests",
};
pub const ENTRA_GUEST_003: Meta = Meta {
    id: "ENTRA-GUEST-003",
    section: "Guest Access",
    setting: "Email-verified users joining the tenant",
    description: "Email-verified users cannot self-join the organisation",
};

pub fn check_guest_settings(ctx: &Ctx) -> Result<Vec<Finding>> {
    let policy = ctx.authz()?;
    let guest_role = policy["guestUserRoleId"].as_str().unwrap_or("");
    let (status, desc) = match guest_role.to_lowercase().as_str() {
        GUEST_ROLE_RESTRICTED => (FindingStatus::Pass, "Restricted guest user access (most restrictive)"),
        GUEST_ROLE_LIMITED => (FindingStatus::Warning, "Guest users have limited access (default): guests can enumerate groups and other users"),
        GUEST_ROLE_MEMBER => (FindingStatus::Fail, "Guest users have the same access as members"),
        _ => (FindingStatus::Warning, "Unknown guest role id"),
    };
    let guest = ctx
        .finding(&ENTRA_GUEST_001)
        .status(status)
        .current_value(format!("{desc} ({guest_role})"))
        .expected_value(format!("guestUserRoleId = {GUEST_ROLE_RESTRICTED} (Guest user access is restricted to properties and memberships of their own directory objects)"))
        .remediation("Entra admin center > External Identities > External collaboration settings > Guest user access: 'Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)'.")
        .build();

    let invites = policy["allowInvitesFrom"].as_str().unwrap_or("unknown");
    let invite_status = match invites {
        "none" | "adminsAndGuestInviters" => FindingStatus::Pass,
        "adminsGuestInvitersAndAllMembers" => FindingStatus::Warning,
        "everyone" => FindingStatus::Fail,
        _ => FindingStatus::Warning,
    };
    let invite = ctx
        .finding(&ENTRA_GUEST_002)
        .status(invite_status)
        .current_value(format!("allowInvitesFrom = {invites}"))
        .expected_value("allowInvitesFrom = adminsAndGuestInviters (or none)")
        .remediation("External collaboration settings > Guest invite settings: 'Only users assigned to specific admin roles can invite guest users'.")
        .build();

    let email_join = policy["allowEmailVerifiedUsersToJoinOrganization"]
        .as_bool()
        .unwrap_or(false);
    let join = ctx
        .finding(&ENTRA_GUEST_003)
        .status(if email_join {
            FindingStatus::Fail
        } else {
            FindingStatus::Pass
        })
        .current_value(format!("allowEmailVerifiedUsersToJoinOrganization = {email_join}"))
        .expected_value("allowEmailVerifiedUsersToJoinOrganization = false")
        .remediation("Set authorizationPolicy.allowEmailVerifiedUsersToJoinOrganization to false (Update-MgPolicyAuthorizationPolicy).")
        .build();
    Ok(vec![guest, invite, join])
}

pub const ENTRA_XTAP_001: Meta = Meta {
    id: "ENTRA-XTAP-001",
    section: "Guest Access",
    setting: "Cross-tenant access inbound defaults",
    description: "Default inbound B2B collaboration is not 'allow all users and applications', or partner-specific inbound restrictions exist",
};

/// Whether an inbound B2B setting allows everyone to everything.
pub fn inbound_allows_all(b2b: &Value) -> bool {
    let all = |section: &str| {
        let s = &b2b[section];
        s["accessType"].as_str().is_none_or(|a| a == "allowed")
            && s["targets"].as_array().is_none_or(|t| {
                t.iter().any(|x| {
                    x["target"]
                        .as_str()
                        .is_some_and(|v| v == "AllUsers" || v == "AllApplications")
                })
            })
    };
    all("usersAndGroups") && all("applications")
}

pub async fn check_cross_tenant_access(ctx: &Ctx<'_>) -> Result<Finding> {
    let default = ctx
        .graph
        .get_json("/v1.0/policies/crossTenantAccessPolicy/default")
        .await?;
    let allow_all = inbound_allows_all(&default["b2bCollaborationInbound"]);
    let partners: Vec<Value> = ctx
        .graph
        .get_all("/v1.0/policies/crossTenantAccessPolicy/partners")
        .await
        .unwrap_or_default();
    let restricted_partners = partners
        .iter()
        .filter(|p| {
            p["b2bCollaborationInbound"].is_object()
                && !inbound_allows_all(&p["b2bCollaborationInbound"])
        })
        .count();
    let (status, current) = if !allow_all {
        (
            FindingStatus::Pass,
            "Default inbound B2B collaboration is restricted".to_string(),
        )
    } else if restricted_partners > 0 {
        (
            FindingStatus::Warning,
            format!("Default inbound B2B collaboration allows all users and applications; {restricted_partners} of {} partner(s) restrict inbound access", partners.len()),
        )
    } else {
        (
            FindingStatus::Warning,
            format!("Default inbound B2B collaboration allows all users and applications and no partner restrictions exist ({} partners). The invitation domain allow/block list is not readable via Graph.", partners.len()),
        )
    };
    Ok(ctx
        .finding(&ENTRA_XTAP_001)
        .status(status)
        .current_value(current)
        .expected_value("crossTenantAccessPolicy/default b2bCollaborationInbound usersAndGroups or applications restricted (accessType blocked or specific targets), or per-partner restrictions")
        .remediation("Entra admin center > External Identities > Cross-tenant access settings > Default settings > Inbound: restrict B2B collaboration users/applications, then add partner organisations with explicit settings; also set the collaboration restrictions domain allow list.")
        .build())
}

// ---------------------------------------------------------------------------
// Device registration policy
// ---------------------------------------------------------------------------

pub const ENTRA_DEVICE_001: Meta = Meta {
    id: "ENTRA-DEVICE-001",
    section: "Device Management",
    setting: "Entra join restricted",
    description: "Joining devices to Entra ID is limited to selected users or disabled",
};
pub const ENTRA_DEVICE_003: Meta = Meta {
    id: "ENTRA-DEVICE-003",
    section: "Device Management",
    setting: "Global Administrators not local admins on joined devices",
    description:
        "The Global Administrator role is not added as local administrator during Entra join",
};
pub const ENTRA_DEVICE_004: Meta = Meta {
    id: "ENTRA-DEVICE-004",
    section: "Device Management",
    setting: "Registering users as local admins limited",
    description: "Users who join a device are not automatically local administrators (or only selected users are)",
};
pub const ENTRA_DEVICE_005: Meta = Meta {
    id: "ENTRA-DEVICE-005",
    section: "Device Management",
    setting: "Local Administrator Password Solution (LAPS)",
    description: "Windows LAPS is enabled in the device registration policy",
};

/// `all` / `none` / `selected` / `unknown` from a deviceRegistrationMembership object.
pub fn membership_kind(v: &Value) -> &'static str {
    match v["@odata.type"].as_str() {
        Some("#microsoft.graph.allDeviceRegistrationMembership") => "all",
        Some("#microsoft.graph.noDeviceRegistrationMembership") => "none",
        Some("#microsoft.graph.enumeratedDeviceRegistrationMembership") => "selected",
        _ => "unknown",
    }
}

pub fn check_device_registration(ctx: &Ctx, policy: &Result<Value>) -> Vec<Result<Finding>> {
    let policy = match policy {
        Ok(p) => p,
        Err(e) => {
            return (0..4)
                .map(|_| Err(anyhow::anyhow!("deviceRegistrationPolicy unreadable: {e}")))
                .collect()
        }
    };
    let join = membership_kind(&policy["azureADJoin"]["allowedToJoin"]);
    let join_status = match join {
        "selected" | "none" => FindingStatus::Pass,
        "all" => FindingStatus::Fail,
        _ => FindingStatus::Warning,
    };
    let f1 = ctx
        .finding(&ENTRA_DEVICE_001)
        .status(join_status)
        .current_value(format!("azureADJoin.allowedToJoin = {join}"))
        .expected_value("Users may join devices to Microsoft Entra = Selected or None")
        .remediation("Entra admin center > Devices > Device settings: 'Users may join devices to Microsoft Entra' = Selected (Autopilot/IT group) or None.")
        .build();

    let ga_admin = policy["azureADJoin"]["localAdmins"]["enableGlobalAdmins"].as_bool();
    let f3 = ctx
        .finding(&ENTRA_DEVICE_003)
        .status(match ga_admin {
            Some(false) => FindingStatus::Pass,
            Some(true) => FindingStatus::Fail,
            None => FindingStatus::Warning,
        })
        .current_value(format!(
            "azureADJoin.localAdmins.enableGlobalAdmins = {}",
            ga_admin.map(|b| b.to_string()).unwrap_or("not returned".into())
        ))
        .expected_value("enableGlobalAdmins = false")
        .remediation("Devices > Device settings > Manage Additional local administrators on all Microsoft Entra joined devices: 'Global administrator role is added as local administrator' = No.")
        .build();

    let reg = membership_kind(&policy["azureADJoin"]["localAdmins"]["registeringUsers"]);
    let f4 = ctx
        .finding(&ENTRA_DEVICE_004)
        .status(match reg {
            "none" | "selected" => FindingStatus::Pass,
            "all" => FindingStatus::Fail,
            _ => FindingStatus::Warning,
        })
        .current_value(format!("azureADJoin.localAdmins.registeringUsers = {reg}"))
        .expected_value("registeringUsers = None or Selected")
        .remediation("Devices > Device settings > local administrator settings: 'Registering user is added as local administrator' = None (or Selected).")
        .build();

    let laps = policy["localAdminPassword"]["isEnabled"].as_bool();
    let f5 = ctx
        .finding(&ENTRA_DEVICE_005)
        .status(match laps {
            Some(true) => FindingStatus::Pass,
            Some(false) => FindingStatus::Fail,
            None => FindingStatus::Warning,
        })
        .current_value(format!(
            "localAdminPassword.isEnabled = {}",
            laps.map(|b| b.to_string()).unwrap_or("not returned".into())
        ))
        .expected_value("localAdminPassword.isEnabled = true")
        .remediation("Entra admin center > Devices > Device settings: 'Enable Microsoft Entra Local Administrator Password Solution (LAPS)' = Yes, then deploy the Intune LAPS policy.")
        .build();
    vec![Ok(f1), Ok(f3), Ok(f4), Ok(f5)]
}

// ---------------------------------------------------------------------------
// Hybrid authentication
// ---------------------------------------------------------------------------

pub const ENTRA_HYBRID_003: Meta = Meta {
    id: "ENTRA-HYBRID-003",
    section: "Hybrid Identity",
    setting: "Cloud authentication (managed domains, PHS)",
    description: "Every verified domain uses managed authentication and, when directory sync is on, password hash sync is enabled",
};

pub async fn check_cloud_authentication(ctx: &Ctx<'_>) -> Result<Finding> {
    let domains: Vec<Value> = ctx.graph.get_all("/v1.0/domains").await?;
    let federated: Vec<String> = domains
        .iter()
        .filter(|d| d["isVerified"].as_bool().unwrap_or(false))
        .filter(|d| {
            d["authenticationType"]
                .as_str()
                .is_some_and(|t| t.eq_ignore_ascii_case("Federated"))
        })
        .filter_map(|d| d["id"].as_str().map(String::from))
        .collect();
    let org: Vec<Value> = ctx
        .graph
        .get_all("/v1.0/organization")
        .await
        .unwrap_or_default();
    let sync_on = org
        .first()
        .and_then(|o| o["onPremisesSyncEnabled"].as_bool())
        .unwrap_or(false);
    let phs: Option<bool> = if sync_on {
        match ctx
            .graph
            .get_all::<Value>("/beta/directory/onPremisesSynchronization")
            .await
        {
            Ok(cfgs) => Some(cfgs.iter().any(|c| {
                c["features"]["passwordSyncEnabled"]
                    .as_bool()
                    .unwrap_or(false)
            })),
            Err(e) => {
                tracing::warn!("onPremisesSynchronization unavailable: {e}");
                None
            }
        }
    } else {
        None
    };
    let status = if !federated.is_empty() {
        FindingStatus::Fail
    } else if sync_on && phs != Some(true) {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    let mut current = format!(
        "{} federated of {} verified domains; directory sync {}",
        federated.len(),
        domains
            .iter()
            .filter(|d| d["isVerified"].as_bool().unwrap_or(false))
            .count(),
        if sync_on { "on" } else { "off" }
    );
    if sync_on {
        current.push_str(&format!(
            "; password hash sync {}",
            match phs {
                Some(true) => "enabled",
                Some(false) => "disabled",
                None => "unreadable (OnPremDirectorySynchronization.Read.All)",
            }
        ));
    }
    Ok(ctx
        .finding(&ENTRA_HYBRID_003)
        .status(status)
        .current_value(current)
        .expected_value("All verified domains authenticationType = Managed; onPremisesSynchronization.features.passwordSyncEnabled = true when sync is on")
        .remediation("Convert federated domains to managed (Entra Connect: Staged rollout then Convert-MsolDomainToStandard / Update-MgDomain) and enable password hash synchronization in Entra Connect.")
        .affected_resources(federated)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn weak_method_targeting() {
        let all = json!({"state": "enabled", "includeTargets": [{"id": "all_users"}]});
        assert_eq!(weak_method_status(Some(&all)).0, FindingStatus::Fail);
        let group = json!({"state": "enabled", "includeTargets": [{"id": "guid"}]});
        assert_eq!(weak_method_status(Some(&group)).0, FindingStatus::Warning);
        let off = json!({"state": "disabled", "includeTargets": [{"id": "all_users"}]});
        assert_eq!(weak_method_status(Some(&off)).0, FindingStatus::Pass);
        assert_eq!(weak_method_status(None).0, FindingStatus::Pass);
    }

    #[test]
    fn inbound_b2b_defaults() {
        let allow = json!({
            "usersAndGroups": {"accessType": "allowed", "targets": [{"target": "AllUsers", "targetType": "user"}]},
            "applications": {"accessType": "allowed", "targets": [{"target": "AllApplications", "targetType": "application"}]}
        });
        assert!(inbound_allows_all(&allow));
        let blocked = json!({
            "usersAndGroups": {"accessType": "blocked", "targets": [{"target": "AllUsers", "targetType": "user"}]},
            "applications": {"accessType": "allowed", "targets": [{"target": "AllApplications", "targetType": "application"}]}
        });
        assert!(!inbound_allows_all(&blocked));
        let specific = json!({
            "usersAndGroups": {"accessType": "allowed", "targets": [{"target": "group-id", "targetType": "group"}]},
            "applications": {"accessType": "allowed", "targets": [{"target": "AllApplications", "targetType": "application"}]}
        });
        assert!(!inbound_allows_all(&specific));
    }

    #[test]
    fn device_membership_kinds() {
        assert_eq!(
            membership_kind(
                &json!({"@odata.type": "#microsoft.graph.allDeviceRegistrationMembership"})
            ),
            "all"
        );
        assert_eq!(
            membership_kind(
                &json!({"@odata.type": "#microsoft.graph.noDeviceRegistrationMembership"})
            ),
            "none"
        );
        assert_eq!(
            membership_kind(
                &json!({"@odata.type": "#microsoft.graph.enumeratedDeviceRegistrationMembership", "users": []})
            ),
            "selected"
        );
        assert_eq!(membership_kind(&json!(null)), "unknown");
    }
}
