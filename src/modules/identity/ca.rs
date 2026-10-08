//! Conditional Access: pure evaluators over policy JSON plus the CA-* checks.
//!
//! A policy counts only when `state == "enabled"`; report-only is surfaced separately where it
//! matters. "Requires X" means X is the only way to satisfy the grant (operator AND, or X is the
//! sole control), so `mfa OR compliantDevice` does not count as requiring MFA.

use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use super::privileged::RoleTiers;
use super::{Ctx, Meta};
use crate::assessment::finding::{Finding, FindingStatus};

pub const PHISHING_RESISTANT_STRENGTH_ID: &str = "00000000-0000-0000-0000-000000000004";
const PHISHING_RESISTANT_COMBINATIONS: &[&str] = &[
    "windowsHelloForBusiness",
    "fido2",
    "x509CertificateMultiFactor",
    "x509CertificateSingleFactor",
];
const MANAGED_DEVICE_CONTROLS: &[&str] = &["compliantDevice", "domainJoinedDevice"];
const APP_PROTECTION_CONTROLS: &[&str] = &["compliantApplication", "approvedApplication"];

// ---------------------------------------------------------------------------
// Authentication strengths
// ---------------------------------------------------------------------------

/// Which authentication strength policies are phishing-resistant: the built-in one, plus any custom
/// strength whose allowed combinations are all phishing-resistant.
#[derive(Debug, Clone, Default)]
pub struct Strengths {
    phishing_resistant: BTreeSet<String>,
    names: BTreeMap<String, String>,
}

impl Strengths {
    pub fn from_policies(policies: &[Value]) -> Self {
        let mut s = Strengths::default();
        s.phishing_resistant
            .insert(PHISHING_RESISTANT_STRENGTH_ID.to_string());
        for p in policies {
            let Some(id) = p["id"].as_str() else { continue };
            if let Some(name) = p["displayName"].as_str() {
                s.names.insert(id.to_string(), name.to_string());
            }
            let combos = strs(&p["allowedCombinations"]);
            if !combos.is_empty()
                && combos
                    .iter()
                    .all(|c| PHISHING_RESISTANT_COMBINATIONS.contains(c))
            {
                s.phishing_resistant.insert(id.to_string());
            }
        }
        s
    }

    pub fn is_phishing_resistant(&self, id: &str) -> bool {
        self.phishing_resistant.contains(id)
    }

    pub fn name(&self, id: &str) -> String {
        self.names
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_string())
    }
}

// ---------------------------------------------------------------------------
// Policy accessors
// ---------------------------------------------------------------------------

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn has(v: &Value, needle: &str) -> bool {
    strs(v).iter().any(|s| s.eq_ignore_ascii_case(needle))
}

pub fn name(p: &Value) -> &str {
    p["displayName"].as_str().unwrap_or("(unnamed policy)")
}

pub fn is_enabled(p: &Value) -> bool {
    p["state"].as_str() == Some("enabled")
}

pub fn is_report_only(p: &Value) -> bool {
    p["state"].as_str() == Some("enabledForReportingButNotEnforced")
}

pub fn targets_all_users(p: &Value) -> bool {
    has(&p["conditions"]["users"]["includeUsers"], "All")
}

pub fn targets_all_apps(p: &Value) -> bool {
    has(
        &p["conditions"]["applications"]["includeApplications"],
        "All",
    )
}

pub fn targets_office365(p: &Value) -> bool {
    let apps = &p["conditions"]["applications"]["includeApplications"];
    has(apps, "All") || has(apps, "Office365")
}

pub fn include_roles(p: &Value) -> Vec<&str> {
    strs(&p["conditions"]["users"]["includeRoles"])
}

pub fn user_actions(p: &Value) -> Vec<&str> {
    strs(&p["conditions"]["applications"]["includeUserActions"])
}

pub fn built_in_controls(p: &Value) -> Vec<&str> {
    strs(&p["grantControls"]["builtInControls"])
}

fn grant_is_and(p: &Value) -> bool {
    p["grantControls"]["operator"]
        .as_str()
        .is_some_and(|o| o.eq_ignore_ascii_case("AND"))
}

pub fn strength_id(p: &Value) -> Option<&str> {
    p["grantControls"]["authenticationStrength"]["id"].as_str()
}

/// True when every way to satisfy the grant is in `accepted` and at least one of `required` is present.
fn grant_requires(p: &Value, required: &[&str], accepted: &[&str]) -> bool {
    let controls = built_in_controls(p);
    let strength = strength_id(p).is_some();
    let present = controls.iter().any(|c| required.contains(c))
        || (strength && required.contains(&"authenticationStrength"));
    if !present {
        return false;
    }
    if grant_is_and(p) {
        return true;
    }
    let others_ok = controls.iter().all(|c| accepted.contains(c));
    let strength_ok = !strength || accepted.contains(&"authenticationStrength");
    others_ok && strength_ok
}

pub fn requires_mfa(p: &Value) -> bool {
    grant_requires(
        p,
        &["mfa", "authenticationStrength"],
        &["mfa", "authenticationStrength"],
    )
}

pub fn requires_phishing_resistant(p: &Value, strengths: &Strengths) -> bool {
    let Some(id) = strength_id(p) else {
        return false;
    };
    strengths.is_phishing_resistant(id)
        && grant_requires(p, &["authenticationStrength"], &["authenticationStrength"])
}

pub fn blocks(p: &Value) -> bool {
    has(&p["grantControls"]["builtInControls"], "block")
}

pub fn requires_managed_device(p: &Value) -> bool {
    grant_requires(p, MANAGED_DEVICE_CONTROLS, MANAGED_DEVICE_CONTROLS)
}

pub fn requires_app_protection(p: &Value) -> bool {
    let accepted = [MANAGED_DEVICE_CONTROLS, APP_PROTECTION_CONTROLS].concat();
    grant_requires(p, APP_PROTECTION_CONTROLS, &accepted)
}

pub fn requires_password_change(p: &Value) -> bool {
    grant_requires(
        p,
        &["passwordChange"],
        &["passwordChange", "mfa", "authenticationStrength"],
    )
}

pub fn client_app_types(p: &Value) -> Vec<&str> {
    strs(&p["conditions"]["clientAppTypes"])
}

pub fn blocks_legacy_auth(p: &Value) -> bool {
    let types = client_app_types(p);
    types.contains(&"exchangeActiveSync") && types.contains(&"other") && blocks(p)
}

pub fn sign_in_risk_levels(p: &Value) -> Vec<&str> {
    strs(&p["conditions"]["signInRiskLevels"])
}

pub fn user_risk_levels(p: &Value) -> Vec<&str> {
    strs(&p["conditions"]["userRiskLevels"])
}

pub fn sign_in_frequency_enabled(p: &Value) -> bool {
    p["sessionControls"]["signInFrequency"]["isEnabled"]
        .as_bool()
        .unwrap_or(false)
}

pub fn sign_in_frequency_every_time(p: &Value) -> bool {
    sign_in_frequency_enabled(p)
        && p["sessionControls"]["signInFrequency"]["frequencyInterval"].as_str()
            == Some("everyTime")
}

pub fn persistent_browser_never(p: &Value) -> bool {
    let pb = &p["sessionControls"]["persistentBrowser"];
    pb["isEnabled"].as_bool().unwrap_or(false) && pb["mode"].as_str() == Some("never")
}

/// `conditions.authenticationFlows.transferMethods` is a comma-separated flag string.
pub fn transfer_methods(p: &Value) -> Vec<String> {
    p["conditions"]["authenticationFlows"]["transferMethods"]
        .as_str()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty() && x != "none")
                .collect()
        })
        .unwrap_or_default()
}

pub fn has_device_filter(p: &Value) -> bool {
    p["conditions"]["devices"]["deviceFilter"]["rule"]
        .as_str()
        .is_some_and(|r| !r.is_empty())
}

pub fn include_platforms(p: &Value) -> Vec<&str> {
    strs(&p["conditions"]["platforms"]["includePlatforms"])
}

/// A policy covers a role when the role is in scope and not excluded.
pub fn covers_role(p: &Value, role_id: &str) -> bool {
    (targets_all_users(p) || has(&p["conditions"]["users"]["includeRoles"], role_id))
        && !has(&p["conditions"]["users"]["excludeRoles"], role_id)
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Exclusions {
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub locations: Vec<String>,
}

pub fn exclusions(p: &Value) -> Exclusions {
    let own = |v: &Value| strs(v).into_iter().map(String::from).collect::<Vec<_>>();
    let users = &p["conditions"]["users"];
    Exclusions {
        users: own(&users["excludeUsers"]),
        groups: own(&users["excludeGroups"]),
        roles: own(&users["excludeRoles"]),
        locations: own(&p["conditions"]["locations"]["excludeLocations"]),
    }
}

fn status_for(full: bool, partial: bool) -> FindingStatus {
    if full {
        FindingStatus::Pass
    } else if partial {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    }
}

fn names(policies: &[&Value]) -> String {
    let v: Vec<&str> = policies.iter().map(|p| name(p)).collect();
    v.join("; ")
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

pub const ENTRA_CA_001: Meta = Meta {
    id: "ENTRA-CA-001",
    section: "Conditional Access",
    setting: "Enabled Conditional Access policies with MFA",
    description: "At least one enabled (not report-only) Conditional Access policy requires MFA",
};
pub const ENTRA_CA_002: Meta = Meta {
    id: "ENTRA-CA-002",
    section: "Conditional Access",
    setting: "All users coverage",
    description: "At least one enabled Conditional Access policy targets All users",
};
pub const ENTRA_CA_003: Meta = Meta {
    id: "ENTRA-CA-003",
    section: "Conditional Access",
    setting: "Policies with excessive exclusions",
    description: "Enabled Conditional Access policies should not carry more than 5 user, group or role exclusions",
};

pub fn check_conditional_access_overview(ctx: &Ctx) -> Result<Vec<Finding>> {
    let all = ctx.ca()?;
    let enabled: Vec<&Value> = all.iter().filter(|p| is_enabled(p)).collect();
    let report_only = all.iter().filter(|p| is_report_only(p)).count();
    let disabled = all.len() - enabled.len() - report_only;
    let summary = format!(
        "{} enabled, {report_only} report-only, {disabled} disabled",
        enabled.len()
    );

    let mfa: Vec<&Value> = enabled
        .iter()
        .copied()
        .filter(|p| requires_mfa(p))
        .collect();
    let mut out = vec![ctx
        .finding(&ENTRA_CA_001)
        .status(if mfa.is_empty() {
            FindingStatus::Fail
        } else {
            FindingStatus::Pass
        })
        .current_value(format!("{summary}; {} enabled policies require MFA", mfa.len()))
        .expected_value("At least one enabled policy whose grant requires MFA or an authentication strength")
        .remediation(
            "Entra admin center > Protection > Conditional Access: create a policy with grant 'Require \
             multifactor authentication' (or an authentication strength) and set it to On, not Report-only.",
        )
        .build()];

    let all_users: Vec<&Value> = enabled
        .iter()
        .copied()
        .filter(|p| targets_all_users(p))
        .collect();
    out.push(
        ctx.finding(&ENTRA_CA_002)
            .status(if all_users.is_empty() {
                FindingStatus::Fail
            } else {
                FindingStatus::Pass
            })
            .current_value(format!(
                "{} enabled policies target All users ({summary})",
                all_users.len()
            ))
            .expected_value("At least one enabled policy with Users = All users")
            .remediation("Target the baseline MFA policy at All users and exclude only the emergency access group.")
            .affected_resources(all_users.iter().map(|p| name(p).to_string()).collect())
            .build(),
    );

    let mut with_exclusions = 0usize;
    let mut large: Vec<String> = Vec::new();
    for p in &enabled {
        let ex = exclusions(p);
        let n = ex.users.len() + ex.groups.len() + ex.roles.len();
        if n > 0 {
            with_exclusions += 1;
        }
        if n > 5 {
            large.push(format!("{} ({n} exclusions)", name(p)));
        }
    }
    out.push(
        ctx.finding(&ENTRA_CA_003)
            .status(if large.is_empty() {
                FindingStatus::Pass
            } else {
                FindingStatus::Warning
            })
            .current_value(format!(
                "{with_exclusions} enabled policies have exclusions; {} have more than 5",
                large.len()
            ))
            .expected_value("No enabled policy with more than 5 user/group/role exclusions")
            .remediation("Collapse per-user exclusions into one owned exclusion group per policy and remove stale entries.")
            .affected_resources(large)
            .build(),
    );
    Ok(out)
}

pub const CA_MFA_ALL_001: Meta = Meta {
    id: "CA-MFA-ALL-001",
    section: "Conditional Access",
    setting: "MFA required for all users",
    description: "An enabled Conditional Access policy requires MFA (or an authentication strength) for All users and All resources, excluding only the emergency access group; tenants without Entra ID P1 rely on Security Defaults",
};

pub fn check_mfa_all_users(ctx: &Ctx) -> Result<Finding> {
    let f = ctx.finding(&CA_MFA_ALL_001).expected_value(
        "Enabled policy: Users = All users, Resources = All resources, Grant = Require MFA or authentication \
         strength, exclusions limited to 1-2 groups (or Security Defaults on without P1)",
    );
    let remediation = "Entra admin center > Protection > Conditional Access > New policy: All users, All \
         resources, Grant 'Require authentication strength' (or MFA); exclude one emergency-access group only. \
         Without Entra ID P1, enable Security Defaults (Entra admin center > Identity > Overview > Properties).";

    if !ctx.has_p1() {
        let sd = ctx.security_defaults()?;
        return Ok(f
            .status(if sd {
                FindingStatus::Pass
            } else {
                FindingStatus::Fail
            })
            .current_value(format!(
                "No Entra ID P1 licence; Security Defaults {}",
                if sd { "enabled" } else { "disabled" }
            ))
            .remediation(remediation)
            .build());
    }

    let policies = ctx.enabled_ca()?;
    let full: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| targets_all_users(p) && targets_all_apps(p) && requires_mfa(p))
        .collect();
    let partial: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| requires_mfa(p) && (targets_all_users(p) || targets_all_apps(p)))
        .filter(|p| !full.contains(p))
        .collect();

    if full.is_empty() {
        let sd = ctx.security_defaults().unwrap_or(false);
        let (status, current) = if sd {
            (
                FindingStatus::Pass,
                "No all-users/all-resources MFA policy, but Security Defaults are enabled"
                    .to_string(),
            )
        } else if partial.is_empty() {
            (
                FindingStatus::Fail,
                "No enabled policy requires MFA for All users and All resources".to_string(),
            )
        } else {
            (
                FindingStatus::Warning,
                format!(
                    "MFA policies exist but none covers All users AND All resources: {}",
                    names(&partial)
                ),
            )
        };
        return Ok(f
            .status(status)
            .current_value(current)
            .remediation(remediation)
            .build());
    }

    // Exclusions: the break-glass group is expected; individual users or many groups are not.
    let mut wide: Vec<String> = Vec::new();
    for p in &full {
        let ex = exclusions(p);
        if !ex.users.is_empty() || ex.groups.len() > 2 {
            wide.push(format!(
                "{}: {} user(s), {} group(s) excluded [{}]",
                name(p),
                ex.users.len(),
                ex.groups.len(),
                ex.users
                    .iter()
                    .chain(ex.groups.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let strengths: Vec<String> = full
        .iter()
        .filter_map(|p| strength_id(p))
        .map(|id| ctx.strengths.name(id))
        .collect();
    let mut current = format!("Enforced by: {}", names(&full));
    if !strengths.is_empty() {
        current.push_str(&format!(
            " (authentication strength: {})",
            strengths.join(", ")
        ));
    }
    if !wide.is_empty() {
        current.push_str(&format!("; broad exclusions: {}", wide.join(" | ")));
    }
    Ok(f.status(if wide.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    })
    .current_value(current)
    .remediation(remediation)
    .affected_resources(wide)
    .build())
}

pub const CA_LEGACYAUTH_001: Meta = Meta {
    id: "CA-LEGACYAUTH-001",
    section: "Conditional Access",
    setting: "Legacy authentication blocked",
    description: "An enabled Conditional Access policy blocks Exchange ActiveSync and Other clients for All users and All resources",
};

pub fn check_legacy_auth(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let blocking: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| blocks_legacy_auth(p))
        .collect();
    let full: Vec<&Value> = blocking
        .iter()
        .copied()
        .filter(|p| targets_all_users(p) && targets_all_apps(p))
        .collect();
    let current = if !full.is_empty() {
        format!(
            "Blocked for All users and All resources by: {}",
            names(&full)
        )
    } else if !blocking.is_empty() {
        format!(
            "Legacy auth is blocked but not for All users and All resources: {}",
            names(&blocking)
        )
    } else {
        "No enabled policy blocks Exchange ActiveSync and Other clients".to_string()
    };
    Ok(ctx
        .finding(&CA_LEGACYAUTH_001)
        .status(status_for(!full.is_empty(), !blocking.is_empty()))
        .current_value(current)
        .expected_value("Enabled policy: All users, All resources, Client apps = Exchange ActiveSync + Other clients, Grant = Block")
        .remediation(
            "Create a Conditional Access policy for All users and All resources with Conditions > Client apps \
             = 'Exchange ActiveSync clients' and 'Other clients', Grant = Block access, state On.",
        )
        .build())
}

pub const CA_MFA_ADMIN_001: Meta = Meta {
    id: "CA-MFA-ADMIN-001",
    section: "Conditional Access",
    setting: "MFA required for administrative roles",
    description: "Privileged directory roles must satisfy a phishing-resistant authentication strength (plain MFA is a partial result)",
};

/// Roles from the tiers not covered by any policy in `matching`.
fn uncovered_roles<'a>(tiers: &'a RoleTiers, matching: &[&Value]) -> Vec<(&'a str, &'a str)> {
    tiers
        .all()
        .filter(|(id, _)| !matching.iter().any(|p| covers_role(p, id)))
        .collect()
}

fn role_list(roles: &[(&str, &str)]) -> Vec<String> {
    roles.iter().map(|(_, n)| n.to_string()).collect()
}

pub fn check_mfa_admin(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let role_scoped =
        |p: &&Value| targets_all_apps(p) && (!include_roles(p).is_empty() || targets_all_users(p));
    let phish: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(role_scoped)
        .filter(|p| requires_phishing_resistant(p, &ctx.strengths))
        .collect();
    let mfa: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(role_scoped)
        .filter(|p| requires_mfa(p))
        .collect();
    let phish_missing = uncovered_roles(&ctx.tiers, &phish);
    let mfa_missing = uncovered_roles(&ctx.tiers, &mfa);

    let (status, current) = if phish_missing.is_empty() {
        (
            FindingStatus::Pass,
            format!(
                "All Tier-0/1 roles require phishing-resistant strength via: {}",
                names(&phish)
            ),
        )
    } else if mfa_missing.is_empty() {
        (
            FindingStatus::Warning,
            format!(
                "All Tier-0/1 roles require MFA ({}) but {} role(s) lack a phishing-resistant strength: {}",
                names(&mfa),
                phish_missing.len(),
                role_list(&phish_missing).join(", ")
            ),
        )
    } else if mfa.is_empty() {
        (
            FindingStatus::Fail,
            "No enabled policy requires MFA for directory roles".to_string(),
        )
    } else {
        (
            FindingStatus::Fail,
            format!(
                "{} Tier-0/1 role(s) not covered by any admin MFA policy: {}",
                mfa_missing.len(),
                role_list(&mfa_missing).join(", ")
            ),
        )
    };
    Ok(ctx
        .finding(&CA_MFA_ADMIN_001)
        .status(status)
        .current_value(current)
        .expected_value("Enabled policy: Directory roles = all Tier-0/1 roles, All resources, Grant = authentication strength 'Phishing-resistant MFA'")
        .remediation(
            "Conditional Access > New policy: Users > Directory roles (select every privileged role), All \
             resources, Grant 'Require authentication strength' = Phishing-resistant MFA.",
        )
        .affected_resources(role_list(&phish_missing))
        .build())
}

pub const CA_PHISHRES_001: Meta = Meta {
    id: "CA-PHISHRES-001",
    section: "Conditional Access",
    setting: "Phishing-resistant MFA for privileged roles",
    description: "Every Tier-0 and Tier-1 directory role is covered by an enabled policy requiring a phishing-resistant authentication strength for all resources",
};

pub fn check_phishres_admin(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let phish: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| targets_all_apps(p) && requires_phishing_resistant(p, &ctx.strengths))
        .collect();
    let missing = uncovered_roles(&ctx.tiers, &phish);
    let tier0_missing: Vec<&(&str, &str)> = missing
        .iter()
        .filter(|(id, _)| ctx.tiers.tier0.contains_key(*id))
        .collect();
    let status = if missing.is_empty() {
        FindingStatus::Pass
    } else if !phish.is_empty() && tier0_missing.is_empty() {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };
    let current = if missing.is_empty() {
        format!("Covered by: {}", names(&phish))
    } else if phish.is_empty() {
        "No enabled policy requires a phishing-resistant authentication strength".to_string()
    } else {
        format!(
            "{} covers some roles; uncovered: {}",
            names(&phish),
            role_list(&missing).join(", ")
        )
    };
    Ok(ctx
        .finding(&CA_PHISHRES_001)
        .status(status)
        .current_value(current)
        .expected_value("All Tier-0/1 roles in scope of a policy with Grant = authentication strength 'Phishing-resistant MFA' (built-in 00000000-0000-0000-0000-000000000004)")
        .remediation("Add every privileged role to the admin policy that requires the Phishing-resistant MFA strength and remove role exclusions.")
        .affected_resources(role_list(&missing))
        .build())
}

pub const CA_PHISHRES_002: Meta = Meta {
    id: "CA-PHISHRES-002",
    section: "Conditional Access",
    setting: "Phishing-resistant MFA for all users",
    description: "An enabled policy requires a phishing-resistant authentication strength for All users and All resources",
};

pub fn check_phishres_all(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let phish: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| requires_phishing_resistant(p, &ctx.strengths))
        .collect();
    let full: Vec<&Value> = phish
        .iter()
        .copied()
        .filter(|p| targets_all_users(p) && targets_all_apps(p))
        .collect();
    let current = if !full.is_empty() {
        format!("All users, all resources: {}", names(&full))
    } else if !phish.is_empty() {
        format!(
            "Phishing-resistant strength required only for a subset: {}",
            names(&phish)
        )
    } else {
        "No enabled policy requires a phishing-resistant authentication strength".to_string()
    };
    Ok(ctx
        .finding(&CA_PHISHRES_002)
        .status(status_for(!full.is_empty(), !phish.is_empty()))
        .current_value(current)
        .expected_value("Enabled policy: All users, All resources, Grant = authentication strength 'Phishing-resistant MFA'")
        .remediation(
            "Roll out passkeys / Windows Hello for Business, then raise the all-users policy grant to \
             'Require authentication strength: Phishing-resistant MFA'.",
        )
        .build())
}

pub const CA_ROLECOVERAGE_001: Meta = Meta {
    id: "CA-ROLECOVERAGE-001",
    section: "Conditional Access",
    setting: "Privileged role coverage by MFA policies",
    description: "Every Tier-0 and Tier-1 role is in scope of an enabled policy that requires MFA for all resources",
};

pub fn check_role_coverage(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let mfa: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| targets_all_apps(p) && requires_mfa(p))
        .collect();
    let missing = uncovered_roles(&ctx.tiers, &mfa);
    let tier0: Vec<String> = missing
        .iter()
        .filter(|(id, _)| ctx.tiers.tier0.contains_key(*id))
        .map(|(_, n)| n.to_string())
        .collect();
    let status = if missing.is_empty() {
        FindingStatus::Pass
    } else if tier0.is_empty() {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };
    Ok(ctx
        .finding(&CA_ROLECOVERAGE_001)
        .status(status)
        .current_value(format!(
            "{} of {} privileged roles uncovered ({} Tier-0)",
            missing.len(),
            ctx.tiers.all().count(),
            tier0.len()
        ))
        .expected_value("0 uncovered roles")
        .remediation("Add the missing roles to the admin MFA policy (Users > Directory roles) and remove role exclusions.")
        .affected_resources(role_list(&missing))
        .build())
}

pub const CA_SIGNINRISK_001: Meta = Meta {
    id: "CA-SIGNINRISK-001",
    section: "Conditional Access",
    setting: "Sign-in risk policy",
    description: "An enabled policy for All users requires MFA (or blocks) for medium and high sign-in risk with sign-in frequency 'every time'",
};

pub fn check_sign_in_risk(ctx: &Ctx) -> Result<Finding> {
    let f = ctx.finding(&CA_SIGNINRISK_001).expected_value(
        "Enabled policy: All users, sign-in risk = medium + high, Grant = Require MFA/authentication strength (or Block), Session = sign-in frequency Every time",
    );
    if !ctx.tenant.has_p2() {
        return Ok(ctx.not_licensed(f, "Entra ID P2"));
    }
    let policies = ctx.enabled_ca()?;
    let risk: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| {
            let l = sign_in_risk_levels(p);
            l.contains(&"high") && (requires_mfa(p) || blocks(p))
        })
        .collect();
    let full: Vec<&Value> = risk
        .iter()
        .copied()
        .filter(|p| {
            sign_in_risk_levels(p).contains(&"medium")
                && targets_all_users(p)
                && (blocks(p) || sign_in_frequency_every_time(p))
        })
        .collect();
    let mut gaps: Vec<String> = Vec::new();
    for p in &risk {
        let mut g = Vec::new();
        if !sign_in_risk_levels(p).contains(&"medium") {
            g.push("medium risk not included");
        }
        if !targets_all_users(p) {
            g.push("not All users");
        }
        if !blocks(p) && !sign_in_frequency_every_time(p) {
            g.push("sign-in frequency not 'every time'");
        }
        if !g.is_empty() {
            gaps.push(format!("{}: {}", name(p), g.join(", ")));
        }
    }
    let current = if !full.is_empty() {
        format!("Enforced by: {}", names(&full))
    } else if !risk.is_empty() {
        format!(
            "Sign-in risk policy present but incomplete. {}",
            gaps.join(" | ")
        )
    } else {
        "No enabled policy acts on medium/high sign-in risk".to_string()
    };
    Ok(f.status(status_for(!full.is_empty(), !risk.is_empty()))
        .current_value(current)
        .remediation(
            "Conditional Access > New policy: All users, All resources, Conditions > Sign-in risk = High + \
             Medium, Grant = Require MFA, Session = Sign-in frequency 'Every time'.",
        )
        .build())
}

pub const CA_USERRISK_001: Meta = Meta {
    id: "CA-USERRISK-001",
    section: "Conditional Access",
    setting: "User risk policy",
    description: "An enabled policy for All users requires a secure password change (or blocks) for high user risk",
};

pub fn check_user_risk(ctx: &Ctx) -> Result<Finding> {
    let f = ctx.finding(&CA_USERRISK_001).expected_value(
        "Enabled policy: All users, user risk = high, Grant = Require password change (with MFA) or Block",
    );
    if !ctx.tenant.has_p2() {
        return Ok(ctx.not_licensed(f, "Entra ID P2"));
    }
    let policies = ctx.enabled_ca()?;
    let risk: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| user_risk_levels(p).contains(&"high"))
        .collect();
    let remediating: Vec<&Value> = risk
        .iter()
        .copied()
        .filter(|p| requires_password_change(p) || blocks(p))
        .collect();
    let full: Vec<&Value> = remediating
        .iter()
        .copied()
        .filter(|p| targets_all_users(p))
        .collect();
    let current = if !full.is_empty() {
        format!("Enforced by: {}", names(&full))
    } else if !remediating.is_empty() {
        format!(
            "Remediation policy exists but not for All users: {}",
            names(&remediating)
        )
    } else if !risk.is_empty() {
        format!(
            "User-risk policy exists but grants neither password change nor block: {}",
            names(&risk)
        )
    } else {
        "No enabled policy acts on high user risk".to_string()
    };
    Ok(f.status(status_for(!full.is_empty(), !remediating.is_empty()))
        .current_value(current)
        .remediation(
            "Conditional Access > New policy: All users, All resources, Conditions > User risk = High, \
             Grant = Require password change (requires MFA).",
        )
        .build())
}

pub const CA_DEVICECODE_001: Meta = Meta {
    id: "CA-DEVICECODE-001",
    section: "Conditional Access",
    setting: "Device code flow and authentication transfer blocked",
    description:
        "An enabled policy blocks the device code flow and authentication transfer for All users",
};

pub async fn check_device_code(ctx: &Ctx<'_>) -> Result<Finding> {
    let mut policies: Vec<Value> = ctx.enabled_ca()?.into_iter().cloned().collect();
    // `authenticationFlows` is still missing from some v1.0 responses; fall back to beta once.
    if !policies
        .iter()
        .any(|p| p["conditions"]["authenticationFlows"].is_object())
    {
        if let Ok(beta) = ctx
            .graph
            .get_all::<Value>("/beta/identity/conditionalAccess/policies")
            .await
        {
            policies = beta.into_iter().filter(is_enabled).collect();
        }
    }
    let flow: Vec<&Value> = policies
        .iter()
        .filter(|p| blocks(p) && !transfer_methods(p).is_empty())
        .collect();
    let full: Vec<&Value> = flow
        .iter()
        .copied()
        .filter(|p| {
            let m = transfer_methods(p);
            targets_all_users(p)
                && m.iter().any(|x| x == "deviceCodeFlow")
                && m.iter().any(|x| x == "authenticationTransfer")
        })
        .collect();
    let current = if !full.is_empty() {
        format!("Blocked for All users by: {}", names(&full))
    } else if !flow.is_empty() {
        let detail: Vec<String> = flow
            .iter()
            .map(|p| {
                format!(
                    "{} blocks [{}]{}",
                    name(p),
                    transfer_methods(p).join(", "),
                    if targets_all_users(p) {
                        ""
                    } else {
                        " (not All users)"
                    }
                )
            })
            .collect();
        detail.join("; ")
    } else {
        "No enabled policy blocks device code flow or authentication transfer".to_string()
    };
    Ok(ctx
        .finding(&CA_DEVICECODE_001)
        .status(status_for(!full.is_empty(), !flow.is_empty()))
        .current_value(current)
        .expected_value("Enabled policy: All users, Conditions > Authentication flows = Device code flow + Authentication transfer, Grant = Block")
        .remediation(
            "Conditional Access > New policy: All users, All resources, Conditions > Authentication flows: \
             select Device code flow and Authentication transfer, Grant = Block; exclude only shared-device accounts.",
        )
        .build())
}

pub const CA_DEVICE_001: Meta = Meta {
    id: "CA-DEVICE-001",
    section: "Conditional Access",
    setting: "Managed device required",
    description: "An enabled policy requires a compliant or Entra hybrid joined device for Office 365 (or all resources) for All users",
};

pub fn check_managed_device(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let device: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| requires_managed_device(p) && targets_office365(p))
        .collect();
    let full: Vec<&Value> = device
        .iter()
        .copied()
        .filter(|p| {
            let platforms = include_platforms(p);
            let desktop = platforms.is_empty()
                || platforms.contains(&"all")
                || (platforms.contains(&"windows") && platforms.contains(&"macOS"));
            targets_all_users(p) && desktop
        })
        .collect();
    let current = if !full.is_empty() {
        format!("Enforced by: {}", names(&full))
    } else if !device.is_empty() {
        format!(
            "Managed-device policy exists but is user- or platform-limited: {}",
            names(&device)
        )
    } else {
        "No enabled policy requires a compliant or hybrid joined device for Office 365".to_string()
    };
    Ok(ctx
        .finding(&CA_DEVICE_001)
        .status(status_for(!full.is_empty(), !device.is_empty()))
        .current_value(current)
        .expected_value("Enabled policy: All users, Office 365 (or All resources), Grant = Require device to be marked as compliant OR Require Microsoft Entra hybrid joined device")
        .remediation(
            "Conditional Access > New policy: All users, Office 365, Platforms Windows + macOS, Grant = \
             'Require device to be marked as compliant' or 'Require Microsoft Entra hybrid joined device' (Require one).",
        )
        .build())
}

pub const CA_DEVICE_002: Meta = Meta {
    id: "CA-DEVICE-002",
    section: "Conditional Access",
    setting: "Managed device required to register security information",
    description: "An enabled policy for All users requires a managed device (or blocks) for the 'Register security information' user action",
};

pub fn check_register_security_info(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let reg: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| {
            user_actions(p)
                .iter()
                .any(|a| a.eq_ignore_ascii_case("urn:user:registersecurityinfo"))
                && (requires_managed_device(p) || blocks(p))
        })
        .collect();
    let full: Vec<&Value> = reg
        .iter()
        .copied()
        .filter(|p| targets_all_users(p))
        .collect();
    let current = if !full.is_empty() {
        format!("Enforced by: {}", names(&full))
    } else if !reg.is_empty() {
        format!("Policy exists but not for All users: {}", names(&reg))
    } else {
        "No enabled policy protects the 'Register security information' user action".to_string()
    };
    Ok(ctx
        .finding(&CA_DEVICE_002)
        .status(status_for(!full.is_empty(), !reg.is_empty()))
        .current_value(current)
        .expected_value("Enabled policy: All users, User actions = Register security information, Grant = Require compliant/hybrid joined device (or Block outside trusted locations)")
        .remediation(
            "Conditional Access > New policy: All users, Target resources > User actions > Register security \
             information, Grant = Require device to be marked as compliant or Require Microsoft Entra hybrid joined device.",
        )
        .build())
}

pub const CA_DEVICE_003: Meta = Meta {
    id: "CA-DEVICE-003",
    section: "Conditional Access",
    setting: "App protection policy required on mobile",
    description: "An enabled policy for All users requires an app protection policy or approved client app on iOS and Android for Office 365",
};

pub fn check_mobile_app_protection(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let mobile: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| requires_app_protection(p) && targets_office365(p))
        .collect();
    let full: Vec<&Value> = mobile
        .iter()
        .copied()
        .filter(|p| {
            let pl = include_platforms(p);
            targets_all_users(p)
                && (pl.contains(&"all") || (pl.contains(&"iOS") && pl.contains(&"android")))
        })
        .collect();
    let current = if !full.is_empty() {
        format!("Enforced by: {}", names(&full))
    } else if !mobile.is_empty() {
        format!(
            "App protection policy exists but is user- or platform-limited: {}",
            names(&mobile)
        )
    } else {
        "No enabled policy requires an app protection policy on iOS/Android".to_string()
    };
    Ok(ctx
        .finding(&CA_DEVICE_003)
        .status(status_for(!full.is_empty(), !mobile.is_empty()))
        .current_value(current)
        .expected_value("Enabled policy: All users, Office 365, Platforms iOS + Android, Grant = Require app protection policy")
        .remediation(
            "Conditional Access > New policy: All users, Office 365, Device platforms iOS and Android, Grant = \
             'Require app protection policy'; pair it with Intune app protection policies.",
        )
        .build())
}

pub const CA_EXCLUSION_001: Meta = Meta {
    id: "CA-EXCLUSION-001",
    section: "Conditional Access",
    setting: "Conditional Access exclusions",
    description: "Exclusions across enabled policies are limited to 1-2 groups, no individual users, and no MFA policy is bypassed from trusted locations",
};

pub async fn check_exclusions(ctx: &Ctx<'_>) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let mut users: BTreeSet<String> = BTreeSet::new();
    let mut groups: BTreeSet<String> = BTreeSet::new();
    let mut roles: BTreeSet<String> = BTreeSet::new();
    let mut trusted_bypass: Vec<String> = Vec::new();
    let mut per_policy: Vec<String> = Vec::new();

    let trusted_locations: BTreeSet<String> = match ctx
        .graph
        .get_all::<Value>("/v1.0/identity/conditionalAccess/namedLocations")
        .await
    {
        Ok(locs) => locs
            .iter()
            .filter(|l| l["isTrusted"].as_bool().unwrap_or(false))
            .filter_map(|l| l["id"].as_str().map(String::from))
            .collect(),
        Err(e) => {
            tracing::warn!("namedLocations unavailable: {e}");
            BTreeSet::new()
        }
    };

    for p in &policies {
        let ex = exclusions(p);
        if ex == Exclusions::default() {
            continue;
        }
        users.extend(ex.users.iter().cloned());
        groups.extend(ex.groups.iter().cloned());
        roles.extend(ex.roles.iter().cloned());
        let trusted = ex
            .locations
            .iter()
            .any(|l| l == "AllTrusted" || trusted_locations.contains(l));
        if trusted && requires_mfa(p) {
            trusted_bypass.push(name(p).to_string());
        }
        per_policy.push(format!(
            "{}: users={} groups={} roles={} locations={}",
            name(p),
            ex.users.len(),
            ex.groups.len(),
            ex.roles.len(),
            ex.locations.join("/")
        ));
    }

    let mut group_names: Vec<String> = Vec::new();
    for id in groups.iter().take(20) {
        let label = match ctx
            .graph
            .get_json(&format!("/v1.0/groups/{id}?$select=displayName"))
            .await
        {
            Ok(g) => format!("{} ({id})", g["displayName"].as_str().unwrap_or("?")),
            Err(_) => id.clone(),
        };
        group_names.push(label);
    }

    let status = if !trusted_bypass.is_empty() {
        FindingStatus::Fail
    } else if !users.is_empty() || groups.len() > 2 {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    let mut current = format!(
        "{} distinct excluded user(s), {} group(s) [{}], {} role(s)",
        users.len(),
        groups.len(),
        group_names.join(", "),
        roles.len()
    );
    if !trusted_bypass.is_empty() {
        current.push_str(&format!(
            "; MFA policies skipped from trusted locations: {}",
            trusted_bypass.join(", ")
        ));
    }
    Ok(ctx
        .finding(&CA_EXCLUSION_001)
        .status(status)
        .current_value(current)
        .expected_value("0 excluded users, at most 2 excluded groups (emergency access, documented service accounts), no trusted-location exclusion on MFA policies")
        .remediation(
            "Replace per-user exclusions with one owned exclusion group, remove 'All trusted locations' \
             exclusions from MFA policies, and review every exclusion quarterly.",
        )
        .affected_resources(per_policy)
        .build())
}

pub const CA_SIGNIN_FREQ_001: Meta = Meta {
    id: "CA-SIGNIN-FREQ-001",
    section: "Conditional Access",
    setting: "Sign-in frequency and persistent browser for administrators",
    description: "Every Tier-0 role is covered by an enabled policy with sign-in frequency set and persistent browser session 'Never'",
};

pub fn check_admin_session(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let session: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| {
            sign_in_frequency_enabled(p) && persistent_browser_never(p) && targets_all_apps(p)
        })
        .collect();
    let missing: Vec<(&str, &str)> = ctx
        .tiers
        .tier0
        .iter()
        .map(|(id, n)| (id.as_str(), n.as_str()))
        .filter(|(id, _)| !session.iter().any(|p| covers_role(p, id)))
        .collect();
    let current = if missing.is_empty() {
        format!("Enforced by: {}", names(&session))
    } else if !session.is_empty() {
        format!(
            "{} set session controls; Tier-0 roles not covered: {}",
            names(&session),
            role_list(&missing).join(", ")
        )
    } else {
        "No enabled policy sets sign-in frequency with persistent browser 'Never' for all resources"
            .to_string()
    };
    Ok(ctx
        .finding(&CA_SIGNIN_FREQ_001)
        .status(status_for(missing.is_empty(), !session.is_empty()))
        .current_value(current)
        .expected_value("Enabled policy: Directory roles = Tier-0 roles, All resources, Session = Sign-in frequency (hours) + Persistent browser session 'Never persistent'")
        .remediation(
            "Conditional Access > admin policy > Session: enable 'Sign-in frequency' (for example 4 hours) \
             and set 'Persistent browser session' to Never persistent.",
        )
        .affected_resources(role_list(&missing))
        .build())
}

pub const CA_PAW_001: Meta = Meta {
    id: "CA-PAW-001",
    section: "Conditional Access",
    setting: "Privileged access workstation enforcement",
    description: "Every Tier-0 role is covered by an enabled policy that restricts sign-in to filtered or compliant devices",
};

pub fn check_paw(ctx: &Ctx) -> Result<Finding> {
    let policies = ctx.enabled_ca()?;
    let paw: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| targets_all_apps(p))
        // A device filter with Block, or a compliant-device grant; an all-users policy only counts
        // when it carries a device filter (otherwise it is the general managed-device baseline).
        .filter(|p| requires_managed_device(p) || (has_device_filter(p) && blocks(p)))
        .filter(|p| !targets_all_users(p) || has_device_filter(p))
        .collect();
    let missing: Vec<(&str, &str)> = ctx
        .tiers
        .tier0
        .iter()
        .map(|(id, n)| (id.as_str(), n.as_str()))
        .filter(|(id, _)| !paw.iter().any(|p| covers_role(p, id)))
        .collect();
    let current = if missing.is_empty() {
        format!("Enforced by: {}", names(&paw))
    } else if !paw.is_empty() {
        format!(
            "{} restricts devices; Tier-0 roles not covered: {}",
            names(&paw),
            role_list(&missing).join(", ")
        )
    } else {
        "No enabled policy restricts privileged roles to filtered or compliant devices".to_string()
    };
    Ok(ctx
        .finding(&CA_PAW_001)
        .status(status_for(missing.is_empty(), !paw.is_empty()))
        .current_value(current)
        .expected_value("Enabled policy: Directory roles = Tier-0 roles, All resources, Conditions > Filter for devices (exclude PAW group) with Grant = Block, or Grant = Require compliant device")
        .remediation(
            "Conditional Access > New policy: Users = privileged roles, All resources, Conditions > Filter for \
             devices: Exclude devices matching the PAW rule (for example device.extensionAttribute1 -eq \"PAW\"), Grant = Block.",
        )
        .affected_resources(role_list(&missing))
        .build())
}

/// Group ids that exclude an account from every enabled policy that blocks or restricts sign-in.
pub fn break_glass_exclusion_groups(policies: &[&Value]) -> BTreeSet<String> {
    let mut sets: Vec<BTreeSet<String>> = policies
        .iter()
        .filter(|p| blocks(p) || requires_mfa(p) || requires_managed_device(p))
        .map(|p| exclusions(p).groups.into_iter().collect())
        .collect();
    let Some(mut common) = sets.pop() else {
        return BTreeSet::new();
    };
    for s in sets {
        common = common.intersection(&s).cloned().collect();
    }
    common
}

#[cfg(test)]
mod tests {
    use super::super::privileged::GLOBAL_ADMIN;
    use super::*;
    use serde_json::json;

    fn policy(state: &str, users: Value, apps: Value, grant: Value) -> Value {
        json!({
            "displayName": "p",
            "state": state,
            "conditions": { "users": users, "applications": apps, "clientAppTypes": ["all"] },
            "grantControls": grant
        })
    }

    #[test]
    fn mfa_requires_sole_or_and_control() {
        let or_mixed = policy(
            "enabled",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "OR", "builtInControls": ["mfa", "compliantDevice"]}),
        );
        assert!(!requires_mfa(&or_mixed));
        let and_mixed = policy(
            "enabled",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "AND", "builtInControls": ["mfa", "compliantDevice"]}),
        );
        assert!(requires_mfa(&and_mixed));
        let strength = policy(
            "enabled",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "OR", "builtInControls": [], "authenticationStrength": {"id": "x"}}),
        );
        assert!(requires_mfa(&strength));
    }

    #[test]
    fn phishing_resistant_strengths() {
        let custom = json!([{
            "id": "custom-1", "displayName": "Keys only",
            "allowedCombinations": ["fido2", "windowsHelloForBusiness"]
        }, {
            "id": "custom-2", "displayName": "Mixed",
            "allowedCombinations": ["fido2", "password,sms"]
        }]);
        let s = Strengths::from_policies(custom.as_array().unwrap());
        assert!(s.is_phishing_resistant(PHISHING_RESISTANT_STRENGTH_ID));
        assert!(s.is_phishing_resistant("custom-1"));
        assert!(!s.is_phishing_resistant("custom-2"));
        let p = policy(
            "enabled",
            json!({"includeRoles": [GLOBAL_ADMIN]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "OR", "builtInControls": [], "authenticationStrength": {"id": PHISHING_RESISTANT_STRENGTH_ID}}),
        );
        assert!(requires_phishing_resistant(&p, &s));
        assert!(covers_role(&p, GLOBAL_ADMIN));
        assert!(!covers_role(&p, "e8611ab8-c189-46e8-94e1-60213ab1f814"));
    }

    #[test]
    fn report_only_is_not_enabled() {
        let p = policy(
            "enabledForReportingButNotEnforced",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "OR", "builtInControls": ["mfa"]}),
        );
        assert!(!is_enabled(&p));
        assert!(is_report_only(&p));
    }

    #[test]
    fn legacy_auth_block_needs_both_client_types() {
        let mut p = policy(
            "enabled",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "OR", "builtInControls": ["block"]}),
        );
        p["conditions"]["clientAppTypes"] = json!(["exchangeActiveSync"]);
        assert!(!blocks_legacy_auth(&p));
        p["conditions"]["clientAppTypes"] = json!(["exchangeActiveSync", "other"]);
        assert!(blocks_legacy_auth(&p));
    }

    #[test]
    fn transfer_methods_and_session_controls() {
        let mut p = policy(
            "enabled",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "OR", "builtInControls": ["block"]}),
        );
        p["conditions"]["authenticationFlows"] =
            json!({"transferMethods": "deviceCodeFlow,authenticationTransfer"});
        assert_eq!(
            transfer_methods(&p),
            vec!["deviceCodeFlow", "authenticationTransfer"]
        );
        p["sessionControls"] = json!({
            "signInFrequency": {"isEnabled": true, "frequencyInterval": "everyTime"},
            "persistentBrowser": {"isEnabled": true, "mode": "never"}
        });
        assert!(sign_in_frequency_every_time(&p));
        assert!(persistent_browser_never(&p));
    }

    #[test]
    fn exclusions_and_common_break_glass_group() {
        let mut a = policy(
            "enabled",
            json!({"includeUsers": ["All"], "excludeGroups": ["bg", "svc"], "excludeUsers": ["u1"]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "OR", "builtInControls": ["mfa"]}),
        );
        a["conditions"]["locations"] = json!({"excludeLocations": ["AllTrusted"]});
        let b = policy(
            "enabled",
            json!({"includeUsers": ["All"], "excludeGroups": ["bg"]}),
            json!({"includeApplications": ["All"]}),
            json!({"operator": "OR", "builtInControls": ["block"]}),
        );
        let ex = exclusions(&a);
        assert_eq!(ex.users, vec!["u1"]);
        assert_eq!(ex.locations, vec!["AllTrusted"]);
        let common = break_glass_exclusion_groups(&[&a, &b]);
        assert_eq!(
            common.into_iter().collect::<Vec<_>>(),
            vec!["bg".to_string()]
        );
    }

    #[test]
    fn managed_device_grant_rules() {
        let either = policy(
            "enabled",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["Office365"]}),
            json!({"operator": "OR", "builtInControls": ["compliantDevice", "domainJoinedDevice"]}),
        );
        assert!(requires_managed_device(&either));
        assert!(targets_office365(&either));
        let weak = policy(
            "enabled",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["Office365"]}),
            json!({"operator": "OR", "builtInControls": ["compliantDevice", "mfa"]}),
        );
        assert!(!requires_managed_device(&weak));
        let app = policy(
            "enabled",
            json!({"includeUsers": ["All"]}),
            json!({"includeApplications": ["Office365"]}),
            json!({"operator": "OR", "builtInControls": ["compliantApplication", "compliantDevice"]}),
        );
        assert!(requires_app_protection(&app));
    }
}
