//! Applications and consent: user consent settings, service principal grants and credentials,
//! app registrations and the tenant app management policy.

use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use super::{Ctx, Meta, Shared};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::graph::GraphClient;

pub const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";
pub const EXCHANGE_APP_ID: &str = "00000002-0000-0ff1-ce00-000000000000";
const MICROSOFT_TENANTS: &[&str] = &[
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
];
/// Permissions that read or control tenant-wide data or the directory itself.
pub const HIGH_IMPACT: &[&str] = &[
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "full_access_as_app",
    "Exchange.ManageAsApp",
];
const STALE_APP_DAYS: i64 = 90;
const MAX_OWNER_CALLS: usize = 60;

pub fn is_high_impact(permission: &str) -> bool {
    HIGH_IMPACT
        .iter()
        .any(|p| p.eq_ignore_ascii_case(permission))
}

pub fn is_microsoft_owned(sp: &Value) -> bool {
    sp["appOwnerOrganizationId"]
        .as_str()
        .is_some_and(|o| MICROSOFT_TENANTS.iter().any(|t| t.eq_ignore_ascii_case(o)))
}

fn sp_label(sp: &Value) -> String {
    format!(
        "{} ({})",
        sp["displayName"].as_str().unwrap_or("Unknown"),
        sp["appId"].as_str().unwrap_or_default()
    )
}

/// Everything the app checks need, fetched once. Each piece carries its own error so a single
/// missing permission only blanks the checks that depend on it.
pub struct AppData {
    pub sps: Shared<Vec<Value>>,
    pub apps: Shared<Vec<Value>>,
    /// appRoleId -> permission value, for Microsoft Graph and Exchange Online application roles.
    pub role_names: BTreeMap<String, String>,
    /// Application role grants (`appRoleAssignedTo`) on Graph and Exchange Online.
    pub app_grants: Shared<Vec<Value>>,
    pub delegated_grants: Shared<Vec<Value>>,
}

impl AppData {
    pub async fn load(graph: &GraphClient) -> Self {
        let sps = graph
            .get_all::<Value>(
                "/v1.0/servicePrincipals?$top=999&$select=id,displayName,appId,accountEnabled,appRoleAssignmentRequired,servicePrincipalType,appOwnerOrganizationId,passwordCredentials,keyCredentials",
            )
            .await
            .map_err(|e| e.to_string());
        let apps = graph
            .get_all::<Value>(
                "/v1.0/applications?$top=999&$select=id,displayName,appId,passwordCredentials,keyCredentials,requiredResourceAccess",
            )
            .await
            .map_err(|e| e.to_string());

        let mut role_names = BTreeMap::new();
        let mut grants: Vec<Value> = Vec::new();
        let mut grant_err: Option<String> = None;
        for resource in [GRAPH_APP_ID, EXCHANGE_APP_ID] {
            let resource_sp = match graph
                .get_json(&format!(
                    "/v1.0/servicePrincipals(appId='{resource}')?$select=id,displayName,appRoles"
                ))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    if resource == GRAPH_APP_ID {
                        grant_err = Some(e.to_string());
                    }
                    continue;
                }
            };
            if let Some(roles) = resource_sp["appRoles"].as_array() {
                for r in roles {
                    if let (Some(id), Some(v)) = (r["id"].as_str(), r["value"].as_str()) {
                        role_names.insert(id.to_lowercase(), v.to_string());
                    }
                }
            }
            if let Some(id) = resource_sp["id"].as_str() {
                match graph
                    .get_all::<Value>(&format!(
                        "/v1.0/servicePrincipals/{id}/appRoleAssignedTo?$top=999"
                    ))
                    .await
                {
                    Ok(g) => grants.extend(g),
                    Err(e) => grant_err = Some(e.to_string()),
                }
            }
        }
        let app_grants = match grant_err {
            Some(e) if grants.is_empty() => Err(e),
            _ => Ok(grants),
        };
        let delegated_grants = graph
            .get_all::<Value>("/v1.0/oauth2PermissionGrants?$top=999")
            .await
            .map_err(|e| e.to_string());

        AppData {
            sps,
            apps,
            role_names,
            app_grants,
            delegated_grants,
        }
    }

    fn sps(&self) -> Result<&[Value]> {
        super::shared(&self.sps).map(Vec::as_slice)
    }

    fn apps(&self) -> Result<&[Value]> {
        super::shared(&self.apps).map(Vec::as_slice)
    }

    pub fn role_name(&self, app_role_id: &str) -> Option<&str> {
        self.role_names
            .get(&app_role_id.to_lowercase())
            .map(String::as_str)
    }

    /// High-impact permissions held by each service principal id: application roles plus
    /// tenant-wide (AllPrincipals) delegated grants.
    pub fn high_impact_by_sp(&self) -> Result<BTreeMap<String, BTreeSet<String>>> {
        let grants = super::shared(&self.app_grants)?;
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for g in grants {
            let (Some(sp), Some(role)) = (g["principalId"].as_str(), g["appRoleId"].as_str())
            else {
                continue;
            };
            if let Some(name) = self.role_name(role).filter(|n| is_high_impact(n)) {
                out.entry(sp.to_string())
                    .or_default()
                    .insert(name.to_string());
            }
        }
        if let Ok(delegated) = &self.delegated_grants {
            for g in delegated {
                if g["consentType"].as_str() != Some("AllPrincipals") {
                    continue;
                }
                let Some(client) = g["clientId"].as_str() else {
                    continue;
                };
                for scope in g["scope"].as_str().unwrap_or("").split_whitespace() {
                    if is_high_impact(scope) {
                        out.entry(client.to_string())
                            .or_default()
                            .insert(format!("{scope} (delegated, all users)"));
                    }
                }
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Consent and app creation
// ---------------------------------------------------------------------------

pub const ENTRA_CONSENT_001: Meta = Meta {
    id: "ENTRA-CONSENT-001",
    section: "Application Consent",
    setting: "User consent to applications",
    description: "Users cannot consent to applications, or only to verified publishers requesting low-impact permissions",
};

/// (status, description) for the user consent policies assigned to the default user role.
pub fn evaluate_consent(policies: &[&str]) -> (FindingStatus, String) {
    let for_self: Vec<&str> = policies
        .iter()
        .copied()
        .filter(|p| p.starts_with("ManagePermissionGrantsForSelf."))
        .collect();
    if for_self.is_empty() {
        return (
            FindingStatus::Pass,
            "User consent disabled (no ManagePermissionGrantsForSelf policy)".into(),
        );
    }
    if for_self
        .iter()
        .all(|p| p.ends_with("microsoft-user-default-low"))
    {
        return (
            FindingStatus::Pass,
            "User consent limited to verified publishers requesting low-impact permissions (microsoft-user-default-low)".into(),
        );
    }
    (
        FindingStatus::Fail,
        format!("Users can consent to applications: {}", for_self.join(", ")),
    )
}

pub fn check_user_consent(ctx: &Ctx) -> Result<Finding> {
    let policy = ctx.authz()?;
    let perms = &policy["defaultUserRolePermissions"];
    let assigned: Vec<&str> = perms["permissionGrantPoliciesAssigned"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let (status, desc) = evaluate_consent(&assigned);
    let create_apps = perms["allowedToCreateApps"].as_bool();
    Ok(ctx
        .finding(&ENTRA_CONSENT_001)
        .status(status)
        .current_value(format!(
            "{desc}; allowedToCreateApps = {}",
            create_apps.map(|b| b.to_string()).unwrap_or("unknown".into())
        ))
        .expected_value("defaultUserRolePermissions.permissionGrantPoliciesAssigned empty or only ManagePermissionGrantsForSelf.microsoft-user-default-low")
        .remediation(
            "Entra admin center > Enterprise applications > Consent and permissions > User consent settings: \
             'Do not allow user consent' (or 'Allow user consent for apps from verified publishers, for selected permissions').",
        )
        .build())
}

pub const ENTRA_APPS_001: Meta = Meta {
    id: "ENTRA-APPS-001",
    section: "Application Consent",
    setting: "Users can register applications",
    description: "Non-admin users cannot register applications",
};

pub fn check_users_can_register_apps(ctx: &Ctx) -> Result<Finding> {
    let policy = ctx.authz()?;
    let allowed = policy["defaultUserRolePermissions"]["allowedToCreateApps"].as_bool();
    Ok(ctx
        .finding(&ENTRA_APPS_001)
        .status(match allowed {
            Some(false) => FindingStatus::Pass,
            Some(true) => FindingStatus::Fail,
            None => FindingStatus::Warning,
        })
        .current_value(format!(
            "allowedToCreateApps = {}",
            allowed.map(|b| b.to_string()).unwrap_or("not returned".into())
        ))
        .expected_value("defaultUserRolePermissions.allowedToCreateApps = false")
        .remediation("Entra admin center > Identity > Users > User settings: 'Users can register applications' = No.")
        .build())
}

pub const ENTRA_CONSENT_002: Meta = Meta {
    id: "ENTRA-CONSENT-002",
    section: "Application Consent",
    setting: "Admin consent workflow",
    description: "The admin consent request workflow is enabled with at least one reviewer",
};

pub async fn check_admin_consent_workflow(ctx: &Ctx<'_>) -> Result<Finding> {
    let policy = ctx
        .graph
        .get_json("/v1.0/policies/adminConsentRequestPolicy")
        .await?;
    let enabled = policy["isEnabled"].as_bool().unwrap_or(false);
    let reviewers = policy["reviewers"].as_array().map(Vec::len).unwrap_or(0);
    let status = if enabled && reviewers > 0 {
        FindingStatus::Pass
    } else if enabled {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };
    Ok(ctx
        .finding(&ENTRA_CONSENT_002)
        .status(status)
        .current_value(format!("isEnabled = {enabled}, {reviewers} reviewer(s)"))
        .expected_value("isEnabled = true with named reviewers")
        .remediation(
            "Entra admin center > Enterprise applications > Admin consent settings: 'Users can request admin \
             consent to apps they are unable to consent to' = Yes, add reviewers, enable notifications.",
        )
        .build())
}

// ---------------------------------------------------------------------------
// Service principals
// ---------------------------------------------------------------------------

pub const ENTRA_ENTAPP_001: Meta = Meta {
    id: "ENTRA-ENTAPP-001",
    section: "Enterprise Applications",
    setting: "Enterprise application inventory",
    description: "Inventory of service principals by origin",
};
pub const ENTRA_ENTAPP_002: Meta = Meta {
    id: "ENTRA-ENTAPP-002",
    section: "Enterprise Applications",
    setting: "Disabled enterprise applications",
    description: "Disabled service principals should be removed once no longer needed",
};
pub const ENTRA_ENTAPP_003: Meta = Meta {
    id: "ENTRA-ENTAPP-003",
    section: "Enterprise Applications",
    setting: "User assignment required",
    description: "Third-party enterprise applications require user assignment",
};
pub const ENTRA_ENTAPP_004: Meta = Meta {
    id: "ENTRA-ENTAPP-004",
    section: "Enterprise Applications",
    setting: "Applications granted high-impact permissions",
    description: "Third-party service principals holding high-impact application permissions or tenant-wide delegated grants (Mail.*, Files.ReadWrite.All, Sites.FullControl.All, Directory.ReadWrite.All, ...)",
};
pub const ENTRA_ENTAPP_005: Meta = Meta {
    id: "ENTRA-ENTAPP-005",
    section: "Enterprise Applications",
    setting: "Service principals with client secrets",
    description: "Third-party service principals carry no password credentials of their own",
};
pub const ENTRA_ENTAPP_022: Meta = Meta {
    id: "ENTRA-ENTAPP-022",
    section: "Enterprise Applications",
    setting: "High-privilege applications without owner or recent use",
    description: "Every service principal with high-impact permissions has an owner and signed in within 90 days",
};

pub fn check_sp_inventory(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    let sps = data.sps()?;
    let microsoft = sps.iter().filter(|s| is_microsoft_owned(s)).count();
    let managed_identities = sps
        .iter()
        .filter(|s| s["servicePrincipalType"].as_str() == Some("ManagedIdentity"))
        .count();
    Ok(ctx
        .finding(&ENTRA_ENTAPP_001)
        .status(FindingStatus::Info)
        .current_value(format!(
            "{} service principals: {microsoft} Microsoft, {managed_identities} managed identities, {} other",
            sps.len(),
            sps.len() - microsoft - managed_identities
        ))
        .expected_value("Inventory reviewed for unexpected applications")
        .remediation("Review enterprise applications periodically and remove those no longer used.")
        .build())
}

pub fn check_disabled_sps(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    let disabled: Vec<String> = data
        .sps()?
        .iter()
        .filter(|s| !s["accountEnabled"].as_bool().unwrap_or(true))
        .map(sp_label)
        .collect();
    Ok(ctx
        .finding(&ENTRA_ENTAPP_002)
        .status(if disabled.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Info
        })
        .current_value(format!("{} disabled service principals", disabled.len()))
        .expected_value("Disabled applications removed when no longer needed")
        .remediation("Delete disabled enterprise applications that will not be re-enabled.")
        .affected_resources(disabled)
        .build())
}

pub fn check_assignment_required(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    let open: Vec<String> = data
        .sps()?
        .iter()
        .filter(|s| {
            s["accountEnabled"].as_bool().unwrap_or(true)
                && s["servicePrincipalType"].as_str() == Some("Application")
                && !is_microsoft_owned(s)
                && !s["appRoleAssignmentRequired"].as_bool().unwrap_or(false)
        })
        .map(sp_label)
        .collect();
    Ok(ctx
        .finding(&ENTRA_ENTAPP_003)
        .status(if open.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .current_value(format!("{} third-party apps without 'Assignment required'", open.len()))
        .expected_value("appRoleAssignmentRequired = true on third-party enterprise applications")
        .remediation("Enterprise applications > app > Properties: 'Assignment required?' = Yes, then assign users or groups.")
        .affected_resources(open)
        .build())
}

/// Non-Microsoft service principals with high-impact grants: (sp, permissions).
fn high_impact_sps(data: &AppData) -> Result<Vec<(&Value, BTreeSet<String>)>> {
    let sps = data.sps()?;
    let by_sp = data.high_impact_by_sp()?;
    Ok(sps
        .iter()
        .filter(|s| !is_microsoft_owned(s))
        .filter_map(|s| {
            let id = s["id"].as_str()?;
            by_sp.get(id).map(|perms| (s, perms.clone()))
        })
        .collect())
}

pub fn check_high_impact_grants(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    let hits = high_impact_sps(data)?;
    let listed: Vec<String> = hits
        .iter()
        .map(|(s, perms)| {
            format!(
                "{}: {}",
                sp_label(s),
                perms.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        })
        .collect();
    Ok(ctx
        .finding(&ENTRA_ENTAPP_004)
        .status(if listed.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .current_value(format!(
            "{} third-party service principals hold high-impact grants",
            listed.len()
        ))
        .expected_value("Every high-impact grant has a named owner and business justification; unused grants removed")
        .remediation(
            "Enterprise applications > app > Permissions: remove grants that are not justified; prefer \
             resource-specific consent and Exchange RBAC for Applications over tenant-wide Mail.* permissions.",
        )
        .affected_resources(listed)
        .build())
}

pub fn check_sp_credentials(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    let with_secrets: Vec<String> = data
        .sps()?
        .iter()
        .filter(|s| !is_microsoft_owned(s))
        .filter(|s| {
            s["passwordCredentials"]
                .as_array()
                .is_some_and(|c| !c.is_empty())
        })
        .map(|s| {
            format!(
                "{} ({} secret(s))",
                sp_label(s),
                s["passwordCredentials"]
                    .as_array()
                    .map(Vec::len)
                    .unwrap_or(0)
            )
        })
        .collect();
    Ok(ctx
        .finding(&ENTRA_ENTAPP_005)
        .status(if with_secrets.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .current_value(format!(
            "{} third-party service principals carry password credentials",
            with_secrets.len()
        ))
        .expected_value("0 service principals with passwordCredentials (secrets added directly to the enterprise app are invisible in the app registration)")
        .remediation("Remove service-principal-level secrets (Remove-MgServicePrincipalPassword) and use certificates or federated credentials on the application object.")
        .affected_resources(with_secrets)
        .build())
}

pub async fn check_high_impact_hygiene(ctx: &Ctx<'_>, data: &AppData) -> Result<Finding> {
    let hits = high_impact_sps(data)?;
    let sign_ins: Option<BTreeMap<String, String>> = match ctx
        .graph
        .get_all::<Value>("/beta/reports/servicePrincipalSignInActivities")
        .await
    {
        Ok(rows) => Some(
            rows.iter()
                .filter_map(|r| {
                    let app_id = r["appId"].as_str()?;
                    let last = r["lastSignInActivity"]["lastSignInDateTime"].as_str()?;
                    Some((app_id.to_string(), last.to_string()))
                })
                .collect(),
        ),
        Err(e) => {
            tracing::warn!("servicePrincipalSignInActivities unavailable: {e}");
            None
        }
    };
    let now = Utc::now();
    let mut problems: Vec<String> = Vec::new();
    let mut owner_calls = 0usize;
    let mut owners_unchecked = 0usize;
    for (sp, _) in &hits {
        let id = sp["id"].as_str().unwrap_or_default();
        let app_id = sp["appId"].as_str().unwrap_or_default();
        let mut issues: Vec<String> = Vec::new();
        if owner_calls < MAX_OWNER_CALLS {
            owner_calls += 1;
            match ctx
                .graph
                .get_all::<Value>(&format!("/v1.0/servicePrincipals/{id}/owners?$select=id"))
                .await
            {
                Ok(o) if o.is_empty() => issues.push("no owner".into()),
                Ok(_) => {}
                Err(_) => issues.push("owners unreadable".into()),
            }
        } else {
            owners_unchecked += 1;
        }
        if let Some(map) = &sign_ins {
            match map
                .get(app_id)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            {
                Some(t) => {
                    let days = now.signed_duration_since(t.with_timezone(&Utc)).num_days();
                    if days > STALE_APP_DAYS {
                        issues.push(format!("last sign-in {days} days ago"));
                    }
                }
                None => issues.push("no sign-in recorded".into()),
            }
        }
        if !issues.is_empty() {
            problems.push(format!("{}: {}", sp_label(sp), issues.join(", ")));
        }
    }
    let status = if !problems.is_empty() {
        FindingStatus::Fail
    } else if sign_ins.is_none() || owners_unchecked > 0 {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    let mut current = format!(
        "{} high-privilege service principals, {} with an owner or activity problem",
        hits.len(),
        problems.len()
    );
    if sign_ins.is_none() {
        current.push_str(
            "; sign-in activity report unavailable (beta reports/servicePrincipalSignInActivities)",
        );
    }
    if owners_unchecked > 0 {
        current.push_str(&format!(
            "; owners not checked for {owners_unchecked} apps (cap)"
        ));
    }
    Ok(ctx
        .finding(&ENTRA_ENTAPP_022)
        .status(status)
        .current_value(current)
        .expected_value("Every high-privilege service principal has >=1 owner and a sign-in within 90 days")
        .remediation("Assign an owner to each privileged enterprise application and remove or disable those with no sign-in in 90 days.")
        .affected_resources(problems)
        .build())
}

// ---------------------------------------------------------------------------
// App registrations
// ---------------------------------------------------------------------------

pub const ENTRA_APPREG_001: Meta = Meta {
    id: "ENTRA-APPREG-001",
    section: "App Registrations",
    setting: "App registration inventory",
    description: "Inventory of application registrations",
};
pub const ENTRA_APPREG_002: Meta = Meta {
    id: "ENTRA-APPREG-002",
    section: "App Registrations",
    setting: "Expired or expiring credentials",
    description: "App registration secrets and certificates are not expired",
};
pub const ENTRA_APPREG_003: Meta = Meta {
    id: "ENTRA-APPREG-003",
    section: "App Registrations",
    setting: "Excessive Graph permissions",
    description: "No app registration requests more than 10 Microsoft Graph permissions",
};
pub const ENTRA_APPREG_005: Meta = Meta {
    id: "ENTRA-APPREG-005",
    section: "App Registrations",
    setting: "Client secrets on privileged app registrations",
    description: "No app registration requesting high-impact application permissions authenticates with a client secret",
};
pub const ENTRA_APPREG_006: Meta = Meta {
    id: "ENTRA-APPREG-006",
    section: "App Registrations",
    setting: "App management policy restricts secrets",
    description:
        "The tenant default app management policy is enabled and restricts password credentials",
};

pub fn check_app_inventory(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    let apps = data.apps()?;
    Ok(ctx
        .finding(&ENTRA_APPREG_001)
        .status(FindingStatus::Info)
        .current_value(format!("{} app registrations", apps.len()))
        .expected_value("Inventory reviewed for unused registrations")
        .remediation("Review app registrations periodically and delete unused ones.")
        .build())
}

pub fn check_app_credential_expiry(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    let now = Utc::now();
    let soon = chrono::Duration::days(30);
    let mut expired: Vec<String> = Vec::new();
    let mut expiring: Vec<String> = Vec::new();
    for app in data.apps()? {
        let name = app["displayName"].as_str().unwrap_or("Unknown");
        for (field, label) in [
            ("passwordCredentials", "secret"),
            ("keyCredentials", "certificate"),
        ] {
            for cred in app[field].as_array().into_iter().flatten() {
                let Some(end) = cred["endDateTime"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                else {
                    continue;
                };
                let end = end.with_timezone(&Utc);
                if end < now {
                    expired.push(format!(
                        "{name} ({label} expired {})",
                        end.format("%Y-%m-%d")
                    ));
                } else if end - now < soon {
                    expiring.push(format!(
                        "{name} ({label} expires {})",
                        end.format("%Y-%m-%d")
                    ));
                }
            }
        }
    }
    let status = if !expired.is_empty() {
        FindingStatus::Fail
    } else if !expiring.is_empty() {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    };
    let mut all = expired.clone();
    all.extend(expiring.iter().cloned());
    Ok(ctx
        .finding(&ENTRA_APPREG_002)
        .status(status)
        .current_value(format!(
            "{} expired, {} expiring within 30 days",
            expired.len(),
            expiring.len()
        ))
        .expected_value("0 expired credentials")
        .remediation("Remove expired secrets and certificates; rotate those expiring soon and alert on expiry.")
        .affected_resources(all)
        .build())
}

pub fn check_app_permission_count(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    let excessive: Vec<String> = data
        .apps()?
        .iter()
        .filter_map(|app| {
            let n: usize = app["requiredResourceAccess"]
                .as_array()?
                .iter()
                .filter(|r| r["resourceAppId"].as_str() == Some(GRAPH_APP_ID))
                .map(|r| r["resourceAccess"].as_array().map(Vec::len).unwrap_or(0))
                .sum();
            (n > 10).then(|| {
                format!(
                    "{} ({n} Graph permissions)",
                    app["displayName"].as_str().unwrap_or("Unknown")
                )
            })
        })
        .collect();
    Ok(ctx
        .finding(&ENTRA_APPREG_003)
        .status(if excessive.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .current_value(format!(
            "{} apps request more than 10 Graph permissions",
            excessive.len()
        ))
        .expected_value("Apps request only the permissions they use")
        .remediation(
            "App registrations > app > API permissions: remove permissions the app does not call.",
        )
        .affected_resources(excessive)
        .build())
}

/// High-impact application permissions (type Role) an app registration requests.
pub fn requested_high_impact_roles(
    app: &Value,
    role_names: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for resource in app["requiredResourceAccess"]
        .as_array()
        .into_iter()
        .flatten()
    {
        for access in resource["resourceAccess"].as_array().into_iter().flatten() {
            if access["type"].as_str() != Some("Role") {
                continue;
            }
            let Some(id) = access["id"].as_str() else {
                continue;
            };
            if let Some(name) = role_names.get(&id.to_lowercase()) {
                if is_high_impact(name) {
                    out.push(name.clone());
                }
            }
        }
    }
    out
}

pub fn check_privileged_apps_with_secrets(ctx: &Ctx, data: &AppData) -> Result<Finding> {
    if data.role_names.is_empty() {
        anyhow::bail!("Microsoft Graph appRoles could not be resolved");
    }
    let mut privileged = 0usize;
    let mut with_secret: Vec<String> = Vec::new();
    for app in data.apps()? {
        let roles = requested_high_impact_roles(app, &data.role_names);
        if roles.is_empty() {
            continue;
        }
        privileged += 1;
        let secrets = app["passwordCredentials"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        if secrets > 0 {
            with_secret.push(format!(
                "{} ({secrets} secret(s); {})",
                app["displayName"].as_str().unwrap_or("Unknown"),
                roles.join(", ")
            ));
        }
    }
    Ok(ctx
        .finding(&ENTRA_APPREG_005)
        .status(if with_secret.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        })
        .current_value(format!(
            "{} of {privileged} app registrations with high-impact application permissions use client secrets",
            with_secret.len()
        ))
        .expected_value("0 privileged app registrations with passwordCredentials; certificates, managed identities or federated credentials instead")
        .remediation("App registrations > app > Certificates & secrets: delete client secrets; upload a certificate (Key Vault) or add a federated credential for CI/CD.")
        .affected_resources(with_secret)
        .build())
}

/// (enabled, password restriction present) from `policies/defaultAppManagementPolicy`.
pub fn evaluate_app_management_policy(policy: &Value) -> (bool, Vec<String>) {
    let enabled = policy["isEnabled"].as_bool().unwrap_or(false);
    let restrictions: Vec<String> = policy["applicationRestrictions"]["passwordCredentials"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["state"].as_str().is_none_or(|s| s == "enabled"))
        .filter_map(|r| r["restrictionType"].as_str())
        .filter(|t| t.starts_with("password") || t.starts_with("symmetricKey"))
        .map(String::from)
        .collect();
    (enabled, restrictions)
}

pub async fn check_app_management_policy(ctx: &Ctx<'_>) -> Result<Finding> {
    let policy = ctx
        .graph
        .get_json("/v1.0/policies/defaultAppManagementPolicy")
        .await?;
    let (enabled, restrictions) = evaluate_app_management_policy(&policy);
    let status = if enabled && !restrictions.is_empty() {
        FindingStatus::Pass
    } else if enabled {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };
    Ok(ctx
        .finding(&ENTRA_APPREG_006)
        .status(status)
        .current_value(format!(
            "isEnabled = {enabled}; password restrictions: {}",
            if restrictions.is_empty() { "none".to_string() } else { restrictions.join(", ") }
        ))
        .expected_value("defaultAppManagementPolicy isEnabled = true with applicationRestrictions.passwordCredentials passwordAddition (block) or passwordLifetime (cap)")
        .remediation("Set the tenant app management policy (PATCH /policies/defaultAppManagementPolicy or Entra admin center > App registrations > App management policies) to block new client secrets or cap their lifetime.")
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn consent_policy_evaluation() {
        assert_eq!(evaluate_consent(&[]).0, FindingStatus::Pass);
        assert_eq!(
            evaluate_consent(&["ManagePermissionGrantsForSelf.microsoft-user-default-low"]).0,
            FindingStatus::Pass
        );
        assert_eq!(
            evaluate_consent(&["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]).0,
            FindingStatus::Fail
        );
        assert_eq!(
            evaluate_consent(&["ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"]).0,
            FindingStatus::Pass
        );
    }

    #[test]
    fn high_impact_roles_resolved_from_ids() {
        let mut names = BTreeMap::new();
        names.insert("aaa".to_string(), "Mail.ReadWrite".to_string());
        names.insert("bbb".to_string(), "User.Read.All".to_string());
        let app = json!({"requiredResourceAccess": [{
            "resourceAppId": GRAPH_APP_ID,
            "resourceAccess": [{"id": "AAA", "type": "Role"}, {"id": "bbb", "type": "Role"}, {"id": "aaa", "type": "Scope"}]
        }]});
        assert_eq!(
            requested_high_impact_roles(&app, &names),
            vec!["Mail.ReadWrite"]
        );
    }

    #[test]
    fn app_management_policy_evaluation() {
        let p = json!({"isEnabled": true, "applicationRestrictions": {"passwordCredentials": [
            {"restrictionType": "passwordAddition", "state": "enabled"},
            {"restrictionType": "customPasswordAddition", "state": "disabled"}
        ]}});
        let (enabled, r) = evaluate_app_management_policy(&p);
        assert!(enabled);
        assert_eq!(r, vec!["passwordAddition"]);
        let off = json!({"isEnabled": false});
        assert_eq!(evaluate_app_management_policy(&off), (false, vec![]));
    }

    #[test]
    fn microsoft_owned_detection() {
        assert!(is_microsoft_owned(
            &json!({"appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a"})
        ));
        assert!(!is_microsoft_owned(
            &json!({"appOwnerOrganizationId": "11111111-1111-1111-1111-111111111111"})
        ));
        assert!(is_high_impact("mail.readwrite"));
        assert!(!is_high_impact("User.Read"));
    }
}
