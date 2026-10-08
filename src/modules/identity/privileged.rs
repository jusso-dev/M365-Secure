//! Privileged access: who holds Tier-0/Tier-1 roles, how (permanent vs PIM), and the checks built
//! on that inventory (admin hygiene, break-glass, PIM policy, access reviews, partner DAP).

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use super::ca::break_glass_exclusion_groups;
use super::{Ctx, DirectoryRole, Meta, Shared};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::graph::GraphClient;

pub const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
pub const PRIVILEGED_ROLE_ADMIN: &str = "e8611ab8-c189-46e8-94e1-60213ab1f814";
const STALE_ADMIN_DAYS: i64 = 45;
const BREAK_GLASS_TEST_DAYS: i64 = 90;
const MAX_USER_DETAIL_CALLS: usize = 300;
const PARTNER_REFERENCE: &str = "#microsoft.graph.directoryObjectPartnerReference";

// ---------------------------------------------------------------------------
// Role tiers (controls/role-tiers.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct RoleTiers {
    pub tier0: BTreeMap<String, String>,
    pub tier1: BTreeMap<String, String>,
}

impl RoleTiers {
    pub fn load() -> Self {
        let raw: Value = serde_json::from_str(include_str!("../../../controls/role-tiers.json"))
            .expect("controls/role-tiers.json is valid JSON");
        let tier = |n: &str| -> BTreeMap<String, String> {
            raw["tiers"][n]["roles"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.to_lowercase(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default()
        };
        RoleTiers {
            tier0: tier("0"),
            tier1: tier("1"),
        }
    }

    pub fn is_privileged(&self, role_id: &str) -> bool {
        let id = role_id.to_lowercase();
        self.tier0.contains_key(&id) || self.tier1.contains_key(&id)
    }

    pub fn name(&self, role_id: &str) -> String {
        let id = role_id.to_lowercase();
        self.tier0
            .get(&id)
            .or_else(|| self.tier1.get(&id))
            .cloned()
            .unwrap_or(id)
    }

    pub fn all(&self) -> impl Iterator<Item = (&str, &str)> {
        self.tier0
            .iter()
            .chain(self.tier1.iter())
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Privileged member inventory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Member {
    pub id: String,
    pub kind: String,
    pub display_name: String,
    pub upn: String,
    /// Tier-0/1 role ids held (active, including PIM activations).
    pub roles: BTreeSet<String>,
    /// Subset of `roles` held as permanent active assignments.
    pub permanent_roles: BTreeSet<String>,
    pub via_group: Option<String>,
    /// `/users/{id}` with accountEnabled, onPremisesSyncEnabled, assignedPlans, signInActivity.
    pub detail: Option<Value>,
}

impl Member {
    fn new(id: &str, kind: &str, principal: &Value) -> Self {
        Member {
            id: id.to_string(),
            kind: kind.to_string(),
            display_name: principal["displayName"].as_str().unwrap_or("").to_string(),
            upn: principal["userPrincipalName"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            roles: BTreeSet::new(),
            permanent_roles: BTreeSet::new(),
            via_group: None,
            detail: None,
        }
    }

    pub fn is_user(&self) -> bool {
        self.kind == "user"
    }

    pub fn label(&self) -> String {
        if self.upn.is_empty() {
            format!("{} [{}]", self.display_name, self.kind)
        } else {
            self.upn.clone()
        }
    }

    pub fn has_role(&self, role_id: &str) -> bool {
        self.roles.contains(&role_id.to_lowercase())
    }

    pub fn is_permanent(&self, role_id: &str) -> bool {
        self.permanent_roles.contains(&role_id.to_lowercase())
    }

    pub fn account_enabled(&self) -> bool {
        self.detail
            .as_ref()
            .and_then(|d| d["accountEnabled"].as_bool())
            .unwrap_or(true)
    }

    /// `Some(true)` when the account is cloud-only; `None` when the attribute could not be read.
    pub fn cloud_only(&self) -> Option<bool> {
        self.detail
            .as_ref()
            .map(|d| !d["onPremisesSyncEnabled"].as_bool().unwrap_or(false))
    }

    pub fn is_onmicrosoft(&self) -> bool {
        self.upn.to_lowercase().ends_with(".onmicrosoft.com")
    }

    pub fn last_sign_in(&self) -> Option<DateTime<Utc>> {
        let act = self.detail.as_ref()?.get("signInActivity")?;
        [
            "lastSuccessfulSignInDateTime",
            "lastSignInDateTime",
            "lastNonInteractiveSignInDateTime",
        ]
        .iter()
        .filter_map(|k| act[k].as_str())
        .filter_map(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
        .max()
    }

    /// Service plans (`assignedPlans[].service`) that are enabled for this user; `None` when unreadable.
    pub fn enabled_services(&self) -> Option<BTreeSet<String>> {
        let plans = self.detail.as_ref()?["assignedPlans"].as_array()?;
        Some(
            plans
                .iter()
                .filter(|p| p["capabilityStatus"].as_str() == Some("Enabled"))
                .filter_map(|p| p["service"].as_str().map(String::from))
                .collect(),
        )
    }

    /// Structural definition of an emergency-access candidate: permanent Global Administrator,
    /// cloud-only, on the `*.onmicrosoft.com` domain. Never by display name.
    pub fn is_break_glass_candidate(&self) -> bool {
        self.is_user()
            && self.is_permanent(GLOBAL_ADMIN)
            && self.cloud_only() == Some(true)
            && self.is_onmicrosoft()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Privileged {
    pub members: Vec<Member>,
    /// PIM schedule data was readable, so `permanent_roles` is exact.
    pub pim_available: bool,
    pub pim_error: Option<String>,
    pub eligible_count: usize,
    pub sign_in_available: bool,
}

impl Privileged {
    pub async fn load(graph: &GraphClient, tenant: &TenantInfo, tiers: &RoleTiers) -> Result<Self> {
        let assignments: Vec<Value> = graph
            .get_all("/v1.0/roleManagement/directory/roleAssignments?$expand=principal")
            .await?;

        let mut members: BTreeMap<String, Member> = BTreeMap::new();
        for a in &assignments {
            let Some(role) = a["roleDefinitionId"].as_str() else {
                continue;
            };
            if !tiers.is_privileged(role) {
                continue;
            }
            let principal = &a["principal"];
            let Some(id) = principal["id"].as_str().or(a["principalId"].as_str()) else {
                continue;
            };
            let kind = principal["@odata.type"]
                .as_str()
                .unwrap_or("#microsoft.graph.directoryObject")
                .trim_start_matches("#microsoft.graph.")
                .to_string();
            let m = members
                .entry(id.to_string())
                .or_insert_with(|| Member::new(id, &kind, principal));
            m.roles.insert(role.to_lowercase());
            // Without PIM data every active assignment is permanent.
            m.permanent_roles.insert(role.to_lowercase());
        }

        let mut out = Privileged::default();
        if tenant.has_p2() {
            match graph
                .get_all::<Value>("/v1.0/roleManagement/directory/roleAssignmentSchedules")
                .await
            {
                Ok(schedules) => {
                    out.pim_available = true;
                    for m in members.values_mut() {
                        m.permanent_roles.clear();
                    }
                    for s in &schedules {
                        let (Some(pid), Some(role)) =
                            (s["principalId"].as_str(), s["roleDefinitionId"].as_str())
                        else {
                            continue;
                        };
                        let permanent = s["assignmentType"].as_str() != Some("Activated")
                            && s["scheduleInfo"]["expiration"]["type"]
                                .as_str()
                                .is_none_or(|t| t == "noExpiration");
                        if permanent {
                            if let Some(m) = members.get_mut(pid) {
                                m.permanent_roles.insert(role.to_lowercase());
                            }
                        }
                    }
                    out.eligible_count = graph
                        .get_all::<Value>("/v1.0/roleManagement/directory/roleEligibilitySchedules")
                        .await
                        .map(|v| {
                            v.iter()
                                .filter(|e| {
                                    e["roleDefinitionId"]
                                        .as_str()
                                        .is_some_and(|r| tiers.is_privileged(r))
                                })
                                .count()
                        })
                        .unwrap_or(0);
                }
                Err(e) => out.pim_error = Some(e.to_string()),
            }
        }

        // Expand role-assignable groups one level.
        let groups: Vec<Member> = members
            .values()
            .filter(|m| m.kind == "group")
            .cloned()
            .collect();
        for g in groups {
            let Ok(gm) = graph
                .get_all::<Value>(&format!(
                    "/v1.0/groups/{}/members?$select=id,displayName,userPrincipalName",
                    g.id
                ))
                .await
            else {
                continue;
            };
            for p in &gm {
                let Some(id) = p["id"].as_str() else { continue };
                let kind = p["@odata.type"]
                    .as_str()
                    .unwrap_or("#microsoft.graph.directoryObject")
                    .trim_start_matches("#microsoft.graph.")
                    .to_string();
                let m = members.entry(id.to_string()).or_insert_with(|| {
                    let mut m = Member::new(id, &kind, p);
                    m.via_group = Some(g.display_name.clone());
                    m
                });
                m.roles.extend(g.roles.iter().cloned());
                m.permanent_roles.extend(g.permanent_roles.iter().cloned());
            }
        }

        // User detail: licence footprint, sync state, sign-in activity.
        let mut sign_in_ok = true;
        for m in members
            .values_mut()
            .filter(|m| m.is_user())
            .take(MAX_USER_DETAIL_CALLS)
        {
            let base = "$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,assignedPlans,userType";
            let with_activity = format!("/v1.0/users/{}?{base},signInActivity", m.id);
            let detail = if sign_in_ok {
                match graph.get_json(&with_activity).await {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::warn!("signInActivity unavailable, continuing without it: {e}");
                        sign_in_ok = false;
                        graph
                            .get_json(&format!("/v1.0/users/{}?{base}", m.id))
                            .await
                            .ok()
                    }
                }
            } else {
                graph
                    .get_json(&format!("/v1.0/users/{}?{base}", m.id))
                    .await
                    .ok()
            };
            if let Some(d) = &detail {
                if let Some(u) = d["userPrincipalName"].as_str() {
                    m.upn = u.to_string();
                }
                if let Some(n) = d["displayName"].as_str() {
                    m.display_name = n.to_string();
                }
            }
            m.detail = detail;
        }
        out.sign_in_available = sign_in_ok;
        out.members = members.into_values().collect();
        Ok(out)
    }

    pub fn users(&self) -> impl Iterator<Item = &Member> {
        self.members.iter().filter(|m| m.is_user())
    }

    pub fn global_admins(&self) -> Vec<&Member> {
        self.members
            .iter()
            .filter(|m| m.has_role(GLOBAL_ADMIN))
            .collect()
    }

    pub fn break_glass_candidates(&self) -> Vec<&Member> {
        self.members
            .iter()
            .filter(|m| m.is_break_glass_candidate())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Admin account checks
// ---------------------------------------------------------------------------

pub const ENTRA_ADMIN_001: Meta = Meta {
    id: "ENTRA-ADMIN-001",
    section: "Global Admins",
    setting: "Global Administrator count",
    description: "Between 2 and 4 accounts hold Global Administrator, counting emergency-access candidates separately",
};

pub fn check_global_admin_count(ctx: &Ctx) -> Result<Finding> {
    let priv_ = ctx.privileged()?;
    let gas = priv_.global_admins();
    let (bg, operational): (Vec<&Member>, Vec<&Member>) =
        gas.iter().partition(|m| m.is_break_glass_candidate());
    let total = gas.len();
    let status = if (2..=4).contains(&total) {
        FindingStatus::Pass
    } else if total == 1 || (5..=8).contains(&total) {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };
    Ok(ctx
        .finding(&ENTRA_ADMIN_001)
        .status(status)
        .current_value(format!(
            "{total} Global Administrators ({} operational, {} emergency-access candidates)",
            operational.len(),
            bg.len()
        ))
        .expected_value("2-4 Global Administrators in total")
        .remediation(
            "Entra admin center > Roles and administrators > Global Administrator: keep 2-4 holders; move \
             everyone else to a scoped role or to a PIM-eligible assignment.",
        )
        .affected_resources(gas.iter().map(|m| m.label()).collect())
        .build())
}

pub const ENTRA_ADMIN_002: Meta = Meta {
    id: "ENTRA-ADMIN-002",
    section: "Privileged Roles",
    setting: "Privileged role inventory",
    description: "Inventory of activated directory roles and their member counts",
};

pub fn check_privileged_role_inventory(ctx: &Ctx) -> Result<Finding> {
    let roles = ctx.roles()?;
    let details: Vec<String> = roles
        .iter()
        .map(|r| format!("{}: {} members", r.name, r.members.len()))
        .collect();
    Ok(ctx
        .finding(&ENTRA_ADMIN_002)
        .status(FindingStatus::Info)
        .current_value(format!("{} roles activated", roles.len()))
        .expected_value("Review role assignments for least privilege")
        .remediation("Review privileged role assignments regularly and remove access that is no longer needed.")
        .details(serde_json::json!({ "roles": details }))
        .build())
}

pub const ENTRA_ADMIN_003: Meta = Meta {
    id: "ENTRA-ADMIN-003",
    section: "Admin Accounts",
    setting: "Dedicated admin accounts",
    description: "Privileged accounts are separated from daily-use accounts (no account holds 3 or more Tier-0/1 roles)",
};

pub fn check_dedicated_admin_accounts(ctx: &Ctx) -> Result<Finding> {
    let priv_ = ctx.privileged()?;
    let admins: Vec<&Member> = priv_
        .users()
        .filter(|m| !m.is_break_glass_candidate())
        .collect();
    let summary: Vec<String> = admins
        .iter()
        .map(|m| {
            let roles: Vec<String> = m.roles.iter().map(|r| ctx.tiers.name(r)).collect();
            format!("{} ({})", m.label(), roles.join(", "))
        })
        .collect();
    let multi: Vec<String> = admins
        .iter()
        .filter(|m| m.roles.len() >= 3)
        .map(|m| format!("{} ({} roles)", m.label(), m.roles.len()))
        .collect();
    let (status, current) = if admins.is_empty() {
        (
            FindingStatus::Info,
            "No privileged user accounts found".to_string(),
        )
    } else if multi.is_empty() {
        (
            FindingStatus::Pass,
            format!("{} privileged accounts, none with 3+ roles", admins.len()),
        )
    } else {
        (
            FindingStatus::Warning,
            format!(
                "{} account(s) hold 3+ privileged roles: {}",
                multi.len(),
                multi.join("; ")
            ),
        )
    };
    Ok(ctx
        .finding(&ENTRA_ADMIN_003)
        .status(status)
        .current_value(current)
        .expected_value("Dedicated admin identities with scoped roles; no account accumulates 3+ privileged roles")
        .remediation("Create dedicated admin accounts (cloud-only, no mailbox) and split role combinations across them.")
        .affected_resources(summary)
        .build())
}

pub const ENTRA_ADMIN_004: Meta = Meta {
    id: "ENTRA-ADMIN-004",
    section: "Admin Accounts",
    setting: "Stale privileged accounts",
    description: "No enabled Tier-0/Tier-1 role holder has gone 45 days without a sign-in (emergency-access candidates excluded)",
};

pub fn check_stale_admins(ctx: &Ctx) -> Result<Finding> {
    let priv_ = ctx.privileged()?;
    if !priv_.sign_in_available {
        anyhow::bail!("signInActivity could not be read (needs AuditLog.Read.All and Entra ID P1)");
    }
    let now = Utc::now();
    let mut stale: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for m in priv_.users() {
        if m.is_break_glass_candidate() || !m.account_enabled() || m.detail.is_none() {
            continue;
        }
        checked += 1;
        match m.last_sign_in() {
            Some(t) => {
                let days = now.signed_duration_since(t).num_days();
                if days > STALE_ADMIN_DAYS {
                    stale.push(format!("{} ({days} days)", m.label()));
                }
            }
            None => stale.push(format!("{} (no sign-in recorded)", m.label())),
        }
    }
    Ok(ctx
        .finding(&ENTRA_ADMIN_004)
        .status(if stale.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        })
        .current_value(format!("{} of {checked} privileged accounts inactive >{STALE_ADMIN_DAYS} days", stale.len()))
        .expected_value(format!("0 privileged accounts without a sign-in in {STALE_ADMIN_DAYS} days"))
        .remediation("Disable or remove the role assignment for privileged accounts inactive for 45 days; automate with an access review or a scheduled script.")
        .affected_resources(stale)
        .build())
}

pub const ENTRA_CLOUDADMIN_001: Meta = Meta {
    id: "ENTRA-CLOUDADMIN-001",
    section: "Admin Accounts",
    setting: "Privileged accounts are cloud-only",
    description: "No Tier-0/Tier-1 role holder is synchronised from on-premises Active Directory",
};

pub fn check_cloud_only_admins(ctx: &Ctx) -> Result<Finding> {
    let priv_ = ctx.privileged()?;
    let synced: Vec<String> = priv_
        .users()
        .filter(|m| m.cloud_only() == Some(false))
        .map(|m| {
            let roles: Vec<String> = m.roles.iter().map(|r| ctx.tiers.name(r)).collect();
            format!("{} ({})", m.label(), roles.join(", "))
        })
        .collect();
    let unknown = priv_.users().filter(|m| m.cloud_only().is_none()).count();
    let status = if !synced.is_empty() {
        FindingStatus::Fail
    } else if unknown > 0 {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    Ok(ctx
        .finding(&ENTRA_CLOUDADMIN_001)
        .status(status)
        .current_value(format!(
            "{} synced privileged account(s), {unknown} unreadable, {} privileged users total",
            synced.len(),
            priv_.users().count()
        ))
        .expected_value("0 privileged accounts with onPremisesSyncEnabled = true")
        .remediation("Replace synced admin accounts with cloud-only accounts (onmicrosoft.com) and remove the role from the synced identity.")
        .affected_resources(synced)
        .build())
}

pub const ENTRA_SYNCADMIN_001: Meta = Meta {
    id: "ENTRA-SYNCADMIN-001",
    section: "Admin Accounts",
    setting: "Synced accounts in Global Administrator",
    description: "No Global Administrator is synchronised from on-premises Active Directory",
};

pub fn check_synced_global_admins(ctx: &Ctx) -> Result<Finding> {
    let priv_ = ctx.privileged()?;
    let synced: Vec<String> = priv_
        .global_admins()
        .iter()
        .filter(|m| m.cloud_only() == Some(false))
        .map(|m| m.label())
        .collect();
    Ok(ctx
        .finding(&ENTRA_SYNCADMIN_001)
        .status(if synced.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        })
        .current_value(format!("{} synced Global Administrator(s)", synced.len()))
        .expected_value("0 Global Administrators with onPremisesSyncEnabled = true")
        .remediation("An on-premises compromise becomes a tenant compromise through a synced Global Administrator. Move the role to a cloud-only account.")
        .affected_resources(synced)
        .build())
}

pub const ENTRA_CLOUDADMIN_002: Meta = Meta {
    id: "ENTRA-CLOUDADMIN-002",
    section: "Admin Accounts",
    setting: "Privileged accounts have no mailbox or Office apps",
    description: "No Tier-0/Tier-1 role holder has an Exchange Online or Microsoft 365 Apps service plan enabled",
};

pub fn check_admin_licence_footprint(ctx: &Ctx) -> Result<Finding> {
    let priv_ = ctx.privileged()?;
    let flagged_services = ["exchange", "MicrosoftOffice"];
    let mut licensed: Vec<String> = Vec::new();
    let mut unknown = 0usize;
    for m in priv_.users().filter(|m| !m.is_break_glass_candidate()) {
        match m.enabled_services() {
            Some(services) => {
                let hits: Vec<&str> = flagged_services
                    .iter()
                    .copied()
                    .filter(|s| services.iter().any(|x| x.eq_ignore_ascii_case(s)))
                    .collect();
                if !hits.is_empty() {
                    licensed.push(format!("{} ({})", m.label(), hits.join(", ")));
                }
            }
            None => unknown += 1,
        }
    }
    let status = if !licensed.is_empty() {
        FindingStatus::Fail
    } else if unknown > 0 {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    Ok(ctx
        .finding(&ENTRA_CLOUDADMIN_002)
        .status(status)
        .current_value(format!(
            "{} privileged account(s) with Exchange/Office plans, {unknown} with unreadable licences",
            licensed.len()
        ))
        .expected_value("0 privileged accounts with an enabled 'exchange' or 'MicrosoftOffice' service plan")
        .remediation("Remove Exchange Online and Microsoft 365 Apps plans from admin accounts (or use Entra ID P2-only licences) so they cannot receive mail or run Office.")
        .affected_resources(licensed)
        .build())
}

// ---------------------------------------------------------------------------
// Break-glass
// ---------------------------------------------------------------------------

pub const ENTRA_BREAKGLASS_001: Meta = Meta {
    id: "ENTRA-BREAKGLASS-001",
    section: "Admin Accounts",
    setting: "Emergency access accounts",
    description: "At least 2 cloud-only permanent Global Administrators on *.onmicrosoft.com use only FIDO2 or certificate authentication, are excluded from Conditional Access through a group, and signed in within 90 days",
};

/// Non-password authentication method types registered on an account, as short names.
pub fn method_types(methods: &[Value]) -> Vec<String> {
    methods
        .iter()
        .filter_map(|m| m["@odata.type"].as_str())
        .map(|t| {
            t.trim_start_matches("#microsoft.graph.")
                .trim_end_matches("AuthenticationMethod")
                .to_string()
        })
        .filter(|t| t != "password")
        .collect()
}

pub fn only_phishing_resistant(types: &[String]) -> bool {
    !types.is_empty()
        && types.iter().all(|t| {
            matches!(
                t.as_str(),
                "fido2" | "x509Certificate" | "platformCredential"
            )
        })
}

pub async fn check_break_glass(ctx: &Ctx<'_>) -> Result<Finding> {
    let priv_ = ctx.privileged()?;
    let f = ctx.finding(&ENTRA_BREAKGLASS_001).expected_value(
        ">=2 accounts: permanent Global Administrator, cloud-only, *.onmicrosoft.com UPN, only FIDO2/certificate methods, excluded via one group from every blocking/MFA policy, last sign-in <= 90 days",
    );
    let remediation = "Create two cloud-only *.onmicrosoft.com accounts with permanent Global Administrator, \
         register only FIDO2 keys or certificates, exclude them via a dedicated group from every Conditional \
         Access policy, alert on each sign-in and test them every 90 days.";

    let candidates = priv_.break_glass_candidates();
    if candidates.len() < 2 {
        let mut note = format!("{} candidate account(s) found", candidates.len());
        if !priv_.pim_available && ctx.tenant.has_p2() {
            note.push_str("; PIM schedules unreadable, permanence assumed");
        }
        return Ok(f
            .status(FindingStatus::Fail)
            .current_value(note)
            .remediation(remediation)
            .affected_resources(candidates.iter().map(|m| m.label()).collect())
            .build());
    }

    let policies = ctx.enabled_ca().unwrap_or_default();
    let exclusion_groups = break_glass_exclusion_groups(&policies);
    let now = Utc::now();
    let mut compliant = 0usize;
    let mut report: Vec<String> = Vec::new();
    for m in &candidates {
        let mut issues: Vec<String> = Vec::new();
        match ctx
            .graph
            .get_all::<Value>(&format!("/v1.0/users/{}/authentication/methods", m.id))
            .await
        {
            Ok(methods) => {
                let types = method_types(&methods);
                if !only_phishing_resistant(&types) {
                    issues.push(format!(
                        "methods: {}",
                        if types.is_empty() {
                            "none".to_string()
                        } else {
                            types.join("/")
                        }
                    ));
                }
            }
            Err(e) => issues.push(format!("methods unreadable ({e})")),
        }
        let groups: BTreeSet<String> = ctx
            .graph
            .get_all::<Value>(&format!("/v1.0/users/{}/memberOf?$select=id", m.id))
            .await
            .map(|g| {
                g.iter()
                    .filter_map(|x| x["id"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if policies.is_empty() {
            // Nothing to be excluded from.
        } else if groups.intersection(&exclusion_groups).next().is_none() {
            issues
                .push("not excluded from all blocking/MFA policies via a common group".to_string());
        }
        match m.last_sign_in() {
            Some(t) => {
                let days = now.signed_duration_since(t).num_days();
                if days > BREAK_GLASS_TEST_DAYS {
                    issues.push(format!("last sign-in {days} days ago"));
                }
            }
            None if priv_.sign_in_available => issues.push("never signed in".to_string()),
            None => issues.push("sign-in activity unreadable".to_string()),
        }
        if issues.is_empty() {
            compliant += 1;
            report.push(format!("{}: OK", m.label()));
        } else {
            report.push(format!("{}: {}", m.label(), issues.join("; ")));
        }
    }
    let status = if compliant >= 2 {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };
    Ok(f.status(status)
        .current_value(format!(
            "{} candidate(s), {compliant} fully compliant",
            candidates.len()
        ))
        .remediation(remediation)
        .affected_resources(report)
        .build())
}

// ---------------------------------------------------------------------------
// PIM
// ---------------------------------------------------------------------------

pub const ENTRA_PIM_001: Meta = Meta {
    id: "ENTRA-PIM-001",
    section: "Privileged Identity Management",
    setting: "Privileged roles are PIM-eligible, not permanent",
    description: "Tier-0/Tier-1 roles are held as PIM eligible assignments; permanent active assignments are limited to emergency-access accounts",
};

pub fn check_pim_usage(ctx: &Ctx) -> Result<Finding> {
    let f = ctx.finding(&ENTRA_PIM_001).expected_value(
        ">=1 eligible assignment and 0 permanent active Tier-0/1 assignments outside emergency-access accounts",
    );
    if !ctx.tenant.has_p2() {
        return Ok(ctx.not_licensed(f, "Entra ID P2"));
    }
    let priv_ = ctx.privileged()?;
    if let Some(e) = &priv_.pim_error {
        anyhow::bail!("roleAssignmentSchedules unreadable: {e}");
    }
    let permanent: Vec<String> = priv_
        .members
        .iter()
        .filter(|m| !m.is_break_glass_candidate())
        .filter(|m| !m.permanent_roles.is_empty())
        .map(|m| {
            let roles: Vec<String> = m
                .permanent_roles
                .iter()
                .map(|r| ctx.tiers.name(r))
                .collect();
            format!("{} ({})", m.label(), roles.join(", "))
        })
        .collect();
    let status = if priv_.eligible_count == 0 {
        FindingStatus::Fail
    } else if permanent.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };
    Ok(f.status(status)
        .current_value(format!(
            "{} eligible privileged assignments; {} principal(s) hold permanent active privileged roles",
            priv_.eligible_count,
            permanent.len()
        ))
        .remediation("PIM > Microsoft Entra roles > Assignments: convert active assignments to eligible; leave only the emergency-access accounts as permanent Global Administrator.")
        .affected_resources(permanent)
        .build())
}

/// Activation and assignment rules from a role management policy (`$expand=rules`).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RolePolicy {
    pub approval_required: Option<bool>,
    pub max_activation_hours: Option<f64>,
    pub enablement: Vec<String>,
    pub eligible_expiration_required: Option<bool>,
}

/// Hours in an ISO 8601 duration such as `PT8H`, `PT30M`, `P1D`, `P1DT12H`.
pub fn iso8601_hours(s: &str) -> Option<f64> {
    let s = s.trim().strip_prefix('P')?;
    let (date, time) = match s.split_once('T') {
        Some((d, t)) => (d, t),
        None => (s, ""),
    };
    let mut hours = 0.0;
    let mut num = String::new();
    for c in date.chars() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
        } else {
            let n: f64 = num.parse().ok()?;
            num.clear();
            hours += match c {
                'D' => n * 24.0,
                'W' => n * 24.0 * 7.0,
                'M' => n * 24.0 * 30.0,
                'Y' => n * 24.0 * 365.0,
                _ => return None,
            };
        }
    }
    for c in time.chars() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
        } else {
            let n: f64 = num.parse().ok()?;
            num.clear();
            hours += match c {
                'H' => n,
                'M' => n / 60.0,
                'S' => n / 3600.0,
                _ => return None,
            };
        }
    }
    Some(hours)
}

pub fn parse_role_policy(rules: &[Value]) -> RolePolicy {
    let mut rp = RolePolicy::default();
    for r in rules {
        match r["id"].as_str().unwrap_or("") {
            "Approval_EndUser_Assignment" => {
                rp.approval_required = r["setting"]["isApprovalRequired"].as_bool();
            }
            "Expiration_EndUser_Assignment" => {
                rp.max_activation_hours = r["maximumDuration"].as_str().and_then(iso8601_hours);
            }
            "Enablement_EndUser_Assignment" => {
                rp.enablement = r["enabledRules"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(String::from)
                            .collect()
                    })
                    .unwrap_or_default();
            }
            "Expiration_Admin_Eligibility" => {
                rp.eligible_expiration_required = r["isExpirationRequired"].as_bool();
            }
            _ => {}
        }
    }
    rp
}

pub struct RolePolicies {
    pub by_role: BTreeMap<String, RolePolicy>,
}

impl RolePolicies {
    pub async fn load(ctx: &Ctx<'_>) -> Result<Self> {
        let mut by_role = BTreeMap::new();
        for (role_id, _) in ctx
            .tiers
            .tier0
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
        {
            let url = format!(
                "/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '{role_id}'&$expand=policy($expand=rules)"
            );
            let assignments: Vec<Value> = ctx.graph.get_all(&url).await?;
            let rules = assignments
                .first()
                .and_then(|a| a["policy"]["rules"].as_array())
                .cloned()
                .unwrap_or_default();
            by_role.insert(role_id.to_string(), parse_role_policy(&rules));
        }
        Ok(RolePolicies { by_role })
    }
}

pub const ENTRA_PIM_004: Meta = Meta {
    id: "ENTRA-PIM-004",
    section: "Privileged Identity Management",
    setting: "Approval required for Global Administrator activation",
    description: "The PIM role setting for Global Administrator requires approval to activate",
};
pub const ENTRA_PIM_005: Meta = Meta {
    id: "ENTRA-PIM-005",
    section: "Privileged Identity Management",
    setting: "Approval required for Privileged Role Administrator activation",
    description:
        "The PIM role setting for Privileged Role Administrator requires approval to activate",
};
pub const ENTRA_PIM_006: Meta = Meta {
    id: "ENTRA-PIM-006",
    section: "Privileged Identity Management",
    setting: "Tier-0 activation duration",
    description: "Maximum activation duration for every Tier-0 role is 8 hours or less",
};
pub const ENTRA_PIM_007: Meta = Meta {
    id: "ENTRA-PIM-007",
    section: "Privileged Identity Management",
    setting: "Justification on Tier-0 activation",
    description: "Activating any Tier-0 role requires a justification",
};
pub const ENTRA_PIM_008: Meta = Meta {
    id: "ENTRA-PIM-008",
    section: "Privileged Identity Management",
    setting: "MFA on Tier-0 activation",
    description: "Activating any Tier-0 role requires multifactor authentication",
};
pub const ENTRA_PIM_009: Meta = Meta {
    id: "ENTRA-PIM-009",
    section: "Privileged Identity Management",
    setting: "Permanent eligible assignments for Tier-0 roles",
    description:
        "Eligible assignments to Tier-0 roles must expire (permanent eligibility not allowed)",
};

pub fn check_pim_policies(ctx: &Ctx, policies: &Shared<RolePolicies>) -> Vec<Result<Finding>> {
    let metas = [
        &ENTRA_PIM_004,
        &ENTRA_PIM_005,
        &ENTRA_PIM_006,
        &ENTRA_PIM_007,
        &ENTRA_PIM_008,
        &ENTRA_PIM_009,
    ];
    if !ctx.tenant.has_p2() {
        return metas
            .iter()
            .map(|m| Ok(ctx.not_licensed(ctx.finding(m), "Entra ID P2")))
            .collect();
    }
    let policies = match policies {
        Ok(p) => p,
        Err(e) => {
            return metas
                .iter()
                .map(|_| Err(anyhow::anyhow!("roleManagementPolicies unreadable: {e}")))
                .collect()
        }
    };
    let pass_fail = |ok: bool| {
        if ok {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        }
    };
    let mut out = Vec::new();

    for (meta, role) in [
        (&ENTRA_PIM_004, GLOBAL_ADMIN),
        (&ENTRA_PIM_005, PRIVILEGED_ROLE_ADMIN),
    ] {
        let approval = policies.by_role.get(role).and_then(|p| p.approval_required);
        out.push(Ok(ctx
            .finding(meta)
            .status(match approval {
                Some(true) => FindingStatus::Pass,
                Some(false) => FindingStatus::Fail,
                None => FindingStatus::Warning,
            })
            .current_value(match approval {
                Some(v) => format!("isApprovalRequired = {v}"),
                None => "Approval rule not present in the role policy".to_string(),
            })
            .expected_value("Role setting 'Require approval to activate' = Yes with named approvers")
            .remediation(format!(
                "PIM > Microsoft Entra roles > Settings > {} > Edit: enable 'Require approval to activate' and select approvers.",
                ctx.tiers.name(role)
            ))
            .build()));
    }

    let tier0: Vec<(&str, &RolePolicy)> = ctx
        .tiers
        .tier0
        .keys()
        .filter_map(|id| policies.by_role.get(id).map(|p| (id.as_str(), p)))
        .collect();

    let too_long: Vec<String> = tier0
        .iter()
        .filter(|(_, p)| p.max_activation_hours.is_none_or(|h| h > 8.0))
        .map(|(id, p)| {
            format!(
                "{} ({})",
                ctx.tiers.name(id),
                p.max_activation_hours
                    .map(|h| format!("{h}h"))
                    .unwrap_or("unset".into())
            )
        })
        .collect();
    out.push(Ok(ctx
        .finding(&ENTRA_PIM_006)
        .status(pass_fail(too_long.is_empty()))
        .current_value(format!(
            "{} Tier-0 role(s) allow activation longer than 8h",
            too_long.len()
        ))
        .expected_value("Activation maximum duration <= 8 hours for every Tier-0 role")
        .remediation(
            "PIM > role settings > 'Activation maximum duration (hours)': set to 8 or less.",
        )
        .affected_resources(too_long)
        .build()));

    for (meta, rule, label) in [
        (
            &ENTRA_PIM_007,
            "Justification",
            "Require justification on activation",
        ),
        (
            &ENTRA_PIM_008,
            "MultiFactorAuthentication",
            "On activation, require Microsoft Entra multifactor authentication",
        ),
    ] {
        let missing: Vec<String> = tier0
            .iter()
            .filter(|(_, p)| !p.enablement.iter().any(|r| r == rule))
            .map(|(id, _)| ctx.tiers.name(id))
            .collect();
        out.push(Ok(ctx
            .finding(meta)
            .status(pass_fail(missing.is_empty()))
            .current_value(format!(
                "{} Tier-0 role(s) without '{rule}' on activation",
                missing.len()
            ))
            .expected_value(format!("'{label}' enabled for every Tier-0 role"))
            .remediation(format!(
                "PIM > role settings > Activation: enable '{label}'."
            ))
            .affected_resources(missing)
            .build()));
    }

    let permanent_eligible: Vec<String> = tier0
        .iter()
        .filter(|(_, p)| p.eligible_expiration_required == Some(false))
        .map(|(id, _)| ctx.tiers.name(id))
        .collect();
    out.push(Ok(ctx
        .finding(&ENTRA_PIM_009)
        .status(if permanent_eligible.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .current_value(format!("{} Tier-0 role(s) allow permanent eligible assignment", permanent_eligible.len()))
        .expected_value("'Allow permanent eligible assignment' = No for every Tier-0 role")
        .remediation("PIM > role settings > Assignment: clear 'Allow permanent eligible assignment' and set an expiry.")
        .affected_resources(permanent_eligible)
        .build()));
    out
}

// ---------------------------------------------------------------------------
// Access reviews
// ---------------------------------------------------------------------------

pub const ENTRA_PIM_002: Meta = Meta {
    id: "ENTRA-PIM-002",
    section: "Access Reviews",
    setting: "Recurring access review of guest users",
    description: "A recurring access review covers guest users",
};
pub const ENTRA_PIM_003: Meta = Meta {
    id: "ENTRA-PIM-003",
    section: "Access Reviews",
    setting: "Recurring access review of privileged roles",
    description: "A recurring access review covers privileged directory roles at least every 12 months with decisions applied automatically",
};

#[derive(Debug, Clone, PartialEq)]
pub struct ReviewSummary {
    pub name: String,
    pub covers_roles: bool,
    pub covers_guests: bool,
    pub recurring: bool,
    pub interval_months: Option<f64>,
    pub auto_apply: bool,
}

pub fn summarise_review(def: &Value) -> ReviewSummary {
    let scope_text = def["scope"].to_string().to_lowercase();
    let covers_roles = scope_text.contains("rolemanagement/directory")
        || scope_text.contains("roledefinitions")
        || scope_text.contains("privilegedaccess/aadroles");
    let covers_guests = scope_text.contains("usertype eq 'guest'")
        || scope_text.contains("usertype%20eq%20'guest'")
        || def["displayName"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("guest");
    let pattern = &def["settings"]["recurrence"]["pattern"];
    let interval = pattern["interval"].as_f64().unwrap_or(1.0);
    let interval_months = match pattern["type"].as_str() {
        Some("daily") => Some(interval / 30.0),
        Some("weekly") => Some(interval * 7.0 / 30.0),
        Some("absoluteMonthly") | Some("relativeMonthly") => Some(interval),
        Some("absoluteYearly") | Some("relativeYearly") => Some(interval * 12.0),
        _ => None,
    };
    let range_type = def["settings"]["recurrence"]["range"]["type"].as_str();
    let recurring = interval_months.is_some() && range_type != Some("numbered")
        || def["settings"]["recurrence"]["range"]["numberOfOccurrences"]
            .as_u64()
            .unwrap_or(0)
            > 1;
    ReviewSummary {
        name: def["displayName"]
            .as_str()
            .unwrap_or("(unnamed)")
            .to_string(),
        covers_roles,
        covers_guests,
        recurring,
        interval_months,
        auto_apply: def["settings"]["autoApplyDecisionsEnabled"]
            .as_bool()
            .unwrap_or(false),
    }
}

pub fn check_access_reviews(ctx: &Ctx, reviews: &Shared<Vec<Value>>) -> Vec<Result<Finding>> {
    if !ctx.tenant.has_p2() {
        return vec![
            Ok(ctx.not_licensed(ctx.finding(&ENTRA_PIM_002), "Entra ID P2 / Governance")),
            Ok(ctx.not_licensed(ctx.finding(&ENTRA_PIM_003), "Entra ID P2 / Governance")),
        ];
    }
    let defs = match reviews {
        Ok(d) => d,
        Err(e) => {
            let err = || anyhow::anyhow!("accessReviews/definitions unreadable: {e}");
            return vec![Err(err()), Err(err())];
        }
    };
    let summaries: Vec<ReviewSummary> = defs.iter().map(summarise_review).collect();

    let guest: Vec<&ReviewSummary> = summaries
        .iter()
        .filter(|s| s.covers_guests && s.recurring)
        .collect();
    let guest_finding = ctx
        .finding(&ENTRA_PIM_002)
        .status(if guest.is_empty() {
            FindingStatus::Fail
        } else {
            FindingStatus::Pass
        })
        .current_value(format!(
            "{} recurring guest review(s) of {} definitions",
            guest.len(),
            defs.len()
        ))
        .expected_value("A recurring access review scoped to guest users")
        .remediation("Identity Governance > Access reviews > New: scope 'Guest users only' across all groups/apps, recurrence quarterly or semi-annual, auto-apply results.")
        .affected_resources(guest.iter().map(|s| s.name.clone()).collect())
        .build();

    let role: Vec<&ReviewSummary> = summaries
        .iter()
        .filter(|s| s.covers_roles && s.recurring)
        .collect();
    let good: Vec<&ReviewSummary> = role
        .iter()
        .copied()
        .filter(|s| s.interval_months.is_some_and(|m| m <= 12.0) && s.auto_apply)
        .collect();
    let detail: Vec<String> = role
        .iter()
        .map(|s| {
            format!(
                "{}: every {} month(s), auto-apply {}",
                s.name,
                s.interval_months
                    .map(|m| format!("{m:.0}"))
                    .unwrap_or("?".into()),
                s.auto_apply
            )
        })
        .collect();
    let (status, current) = if !good.is_empty() {
        (
            FindingStatus::Pass,
            format!("{} compliant review(s): {}", good.len(), detail.join("; ")),
        )
    } else if !role.is_empty() {
        (
            FindingStatus::Warning,
            format!(
                "Role review exists but recurrence >12 months or auto-apply off: {}",
                detail.join("; ")
            ),
        )
    } else {
        (
            FindingStatus::Fail,
            format!(
                "No recurring access review of directory roles ({} definitions)",
                defs.len()
            ),
        )
    };
    let role_finding = ctx
        .finding(&ENTRA_PIM_003)
        .status(status)
        .current_value(current)
        .expected_value("Recurring review of privileged Entra roles, interval <= 12 months, 'Auto apply results to resource' = Enable")
        .remediation("PIM > Microsoft Entra roles > Access reviews > New: select all privileged roles, recurrence quarterly or semi-annual, enable auto-apply.")
        .build();
    vec![Ok(guest_finding), Ok(role_finding)]
}

// ---------------------------------------------------------------------------
// Partner (DAP)
// ---------------------------------------------------------------------------

pub const ENTRA_DAP_001: Meta = Meta {
    id: "ENTRA-DAP-001",
    section: "Partner Access",
    setting: "Legacy delegated admin privileges (DAP)",
    description: "No partner tenant holds directory roles through legacy DAP (AdminAgents / HelpdeskAgents partner references)",
};

pub fn partner_references(roles: &[DirectoryRole]) -> Vec<String> {
    let mut out = Vec::new();
    for r in roles {
        for m in &r.members {
            if m["@odata.type"].as_str() == Some(PARTNER_REFERENCE) {
                out.push(format!(
                    "{} in {} (partner tenant {})",
                    m["displayName"].as_str().unwrap_or("partner group"),
                    r.name,
                    m["externalPartnerTenantId"].as_str().unwrap_or("?")
                ));
            }
        }
    }
    out
}

pub fn check_dap(ctx: &Ctx) -> Result<Finding> {
    let roles = ctx.roles()?;
    let partners = partner_references(roles);
    Ok(ctx
        .finding(&ENTRA_DAP_001)
        .status(if partners.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        })
        .current_value(if partners.is_empty() {
            "No partner references in directory roles. GDAP relationships are not listable from the customer tenant via Graph; review them in the Microsoft 365 admin center > Partner relationships.".to_string()
        } else {
            format!("{} legacy DAP partner reference(s) hold directory roles", partners.len())
        })
        .expected_value("0 directoryObjectPartnerReference members in any directory role; partners use time-bound GDAP")
        .remediation("Microsoft 365 admin center > Settings > Partner relationships: remove DAP and replace it with a GDAP relationship with least-privileged roles and an expiry.")
        .affected_resources(partners)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn iso8601_durations() {
        assert_eq!(iso8601_hours("PT8H"), Some(8.0));
        assert_eq!(iso8601_hours("PT30M"), Some(0.5));
        assert_eq!(iso8601_hours("P1D"), Some(24.0));
        assert_eq!(iso8601_hours("P1DT12H"), Some(36.0));
        assert_eq!(iso8601_hours("garbage"), None);
    }

    #[test]
    fn role_policy_rules() {
        let rules = json!([
            {"id": "Approval_EndUser_Assignment", "setting": {"isApprovalRequired": true}},
            {"id": "Expiration_EndUser_Assignment", "maximumDuration": "PT4H"},
            {"id": "Enablement_EndUser_Assignment", "enabledRules": ["MultiFactorAuthentication", "Justification"]},
            {"id": "Expiration_Admin_Eligibility", "isExpirationRequired": false}
        ]);
        let rp = parse_role_policy(rules.as_array().unwrap());
        assert_eq!(rp.approval_required, Some(true));
        assert_eq!(rp.max_activation_hours, Some(4.0));
        assert_eq!(
            rp.enablement,
            vec!["MultiFactorAuthentication", "Justification"]
        );
        assert_eq!(rp.eligible_expiration_required, Some(false));
    }

    #[test]
    fn review_summary_detects_role_scope_and_recurrence() {
        let def = json!({
            "displayName": "Privileged roles",
            "scope": {"@odata.type": "#microsoft.graph.principalResourceMembershipsScope",
                      "resourceScopes": [{"query": "/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10"}]},
            "settings": {"autoApplyDecisionsEnabled": true,
                         "recurrence": {"pattern": {"type": "absoluteMonthly", "interval": 3}, "range": {"type": "noEnd"}}}
        });
        let s = summarise_review(&def);
        assert!(s.covers_roles);
        assert!(!s.covers_guests);
        assert!(s.recurring);
        assert_eq!(s.interval_months, Some(3.0));
        assert!(s.auto_apply);
    }

    #[test]
    fn break_glass_method_rules() {
        let methods = json!([
            {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"},
            {"@odata.type": "#microsoft.graph.fido2AuthenticationMethod"}
        ]);
        let types = method_types(methods.as_array().unwrap());
        assert_eq!(types, vec!["fido2"]);
        assert!(only_phishing_resistant(&types));
        let weak = vec!["fido2".to_string(), "microsoftAuthenticator".to_string()];
        assert!(!only_phishing_resistant(&weak));
        assert!(!only_phishing_resistant(&[]));
    }

    #[test]
    fn break_glass_candidate_is_structural() {
        let mut m = Member::new(
            "1",
            "user",
            &json!({"userPrincipalName": "bg@contoso.onmicrosoft.com", "displayName": "x"}),
        );
        m.roles.insert(GLOBAL_ADMIN.to_string());
        m.permanent_roles.insert(GLOBAL_ADMIN.to_string());
        m.detail = Some(json!({"onPremisesSyncEnabled": false}));
        assert!(m.is_break_glass_candidate());
        m.detail = Some(json!({"onPremisesSyncEnabled": true}));
        assert!(!m.is_break_glass_candidate());
        m.detail = Some(json!({"onPremisesSyncEnabled": false}));
        m.upn = "bg@contoso.com".to_string();
        assert!(!m.is_break_glass_candidate());
    }

    #[test]
    fn partner_references_are_found_by_type() {
        let roles = vec![DirectoryRole {
            id: "r".into(),
            template_id: GLOBAL_ADMIN.into(),
            name: "Global Administrator".into(),
            members: vec![
                json!({"@odata.type": PARTNER_REFERENCE, "displayName": "AdminAgents", "externalPartnerTenantId": "t"}),
            ],
        }];
        assert_eq!(partner_references(&roles).len(), 1);
    }

    #[test]
    fn role_tiers_load() {
        let t = RoleTiers::load();
        assert!(t.is_privileged(GLOBAL_ADMIN));
        assert!(t.is_privileged(&GLOBAL_ADMIN.to_uppercase()));
        assert_eq!(t.name(GLOBAL_ADMIN), "Global Administrator");
        assert!(t.all().count() >= 10);
    }
}
