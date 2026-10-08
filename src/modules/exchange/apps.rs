//! EXO-APPRBAC-001: applications holding mailbox-wide application permissions are scoped with an
//! application access policy or RBAC for Applications.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

use super::exo::{finding, list_preview, str_of, Exo};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";
const EXO_APP_ID: &str = "00000002-0000-0ff1-ce00-000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxAppGrant {
    /// Service principal object id.
    pub principal_id: String,
    pub display_name: String,
    pub permissions: Vec<String>,
}

/// Application permissions that reach every mailbox unless scoped.
pub fn is_mailbox_permission(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    v.starts_with("mail.")
        || v.starts_with("mailboxsettings.")
        || v.starts_with("calendars.")
        || v.starts_with("contacts.")
        || v == "full_access_as_app"
}

/// Service principals granted mailbox application roles on `resource_sp` (Graph or Exchange Online).
pub fn mailbox_app_grants(resource_sp: &Value, assignments: &[Value]) -> Vec<MailboxAppGrant> {
    let roles: BTreeMap<&str, &str> = resource_sp["appRoles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| Some((str_of(r, "id")?, str_of(r, "value")?)))
                .collect()
        })
        .unwrap_or_default();
    let mut by_principal: BTreeMap<String, MailboxAppGrant> = BTreeMap::new();
    for a in assignments {
        if str_of(a, "principalType").is_some_and(|t| !t.eq_ignore_ascii_case("ServicePrincipal")) {
            continue;
        }
        let Some(role_id) = str_of(a, "appRoleId") else {
            continue;
        };
        let Some(value) = roles.get(role_id) else {
            continue;
        };
        if !is_mailbox_permission(value) {
            continue;
        }
        let Some(pid) = str_of(a, "principalId") else {
            continue;
        };
        let entry = by_principal
            .entry(pid.to_string())
            .or_insert_with(|| MailboxAppGrant {
                principal_id: pid.to_string(),
                display_name: str_of(a, "principalDisplayName").unwrap_or(pid).to_string(),
                permissions: Vec::new(),
            });
        if !entry.permissions.iter().any(|p| p == value) {
            entry.permissions.push(value.to_string());
        }
    }
    by_principal.into_values().collect()
}

/// App ids (application/client ids) that are scoped by an application access policy (RestrictAccess)
/// or an RBAC-for-Applications assignment with a custom resource scope.
pub fn scoped_app_ids(
    access_policies: &[Value],
    role_assignments: &[Value],
    exo_service_principals: &[Value],
) -> HashSet<String> {
    let mut out: HashSet<String> = access_policies
        .iter()
        .filter(|p| {
            str_of(p, "AccessRight").is_some_and(|r| r.eq_ignore_ascii_case("RestrictAccess"))
        })
        .filter_map(|p| str_of(p, "AppId").map(|s| s.to_ascii_lowercase()))
        .collect();

    for a in role_assignments {
        if str_of(a, "RoleAssigneeType")
            .is_some_and(|t| !t.eq_ignore_ascii_case("ServicePrincipal"))
        {
            continue;
        }
        let scoped = str_of(a, "CustomResourceScope").is_some_and(|s| !s.is_empty())
            || str_of(a, "RecipientWriteScope")
                .is_some_and(|s| s.eq_ignore_ascii_case("CustomRecipientScope"))
            || str_of(a, "RecipientReadScope")
                .is_some_and(|s| s.eq_ignore_ascii_case("CustomRecipientScope"));
        if !scoped {
            continue;
        }
        let assignee = str_of(a, "RoleAssignee")
            .or_else(|| str_of(a, "RoleAssigneeName"))
            .or_else(|| str_of(a, "App"))
            .unwrap_or("");
        for sp in exo_service_principals {
            let matches = ["ObjectId", "Identity", "DisplayName", "AppId", "Name"]
                .iter()
                .any(|k| str_of(sp, k).is_some_and(|v| v.eq_ignore_ascii_case(assignee)));
            if matches {
                if let Some(app_id) = str_of(sp, "AppId") {
                    out.insert(app_id.to_ascii_lowercase());
                }
            }
        }
    }
    out
}

/// Grants whose application is not in `scoped`. `principal_app_ids` maps SP object id -> appId.
pub fn unscoped_grants<'g>(
    grants: &'g [MailboxAppGrant],
    principal_app_ids: &BTreeMap<String, String>,
    scoped: &HashSet<String>,
) -> Vec<&'g MailboxAppGrant> {
    grants
        .iter()
        .filter(|g| {
            principal_app_ids
                .get(&g.principal_id)
                .map(|app| !scoped.contains(&app.to_ascii_lowercase()))
                .unwrap_or(true)
        })
        .collect()
}

async fn resource_sp(graph: &GraphClient, app_id: &str) -> Result<Option<Value>> {
    let sps: Vec<Value> = graph
        .get_all::<Value>(&format!(
            "/v1.0/servicePrincipals?$filter=appId eq '{}'&$select=id,appId,appRoles",
            app_id
        ))
        .await?;
    Ok(sps.into_iter().next())
}

async fn principal_app_ids(
    graph: &GraphClient,
    grants: &[MailboxAppGrant],
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let ids: Vec<&str> = grants.iter().map(|g| g.principal_id.as_str()).collect();
    for chunk in ids.chunks(15) {
        let filter = chunk
            .iter()
            .map(|id| format!("'{}'", id))
            .collect::<Vec<_>>()
            .join(",");
        let sps: Vec<Value> = graph
            .get_all::<Value>(&format!(
                "/v1.0/servicePrincipals?$select=id,appId&$filter=id in ({})",
                filter
            ))
            .await?;
        for sp in sps {
            if let (Some(id), Some(app)) = (str_of(&sp, "id"), str_of(&sp, "appId")) {
                out.insert(id.to_string(), app.to_string());
            }
        }
    }
    Ok(out)
}

pub async fn check_app_mailbox_access(
    exo: &Exo<'_>,
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let mut grants: Vec<MailboxAppGrant> = Vec::new();
    for app_id in [GRAPH_APP_ID, EXO_APP_ID] {
        let Some(sp) = resource_sp(graph, app_id).await? else {
            continue;
        };
        let sp_id = str_of(&sp, "id").unwrap_or("");
        let assignments: Vec<Value> = graph
            .get_all::<Value>(&format!(
                "/v1.0/servicePrincipals/{}/appRoleAssignedTo",
                sp_id
            ))
            .await?;
        grants.extend(mailbox_app_grants(&sp, &assignments));
    }

    let base = finding(
        registry,
        "EXO-APPRBAC-001",
        "Exchange Online",
        "Application Access",
        "Application Mailbox Permissions Scoped",
        "Every application with mailbox-wide application permissions is limited to specific mailboxes by an application access policy or RBAC for Applications",
    )
    .expected_value("No service principal holds unscoped Mail.*, MailboxSettings.*, Calendars.*, Contacts.* or full_access_as_app application permissions")
    .remediation(
        "For each listed app either create an RBAC for Applications assignment with a management scope \
         (New-ManagementRoleAssignment -App <appId> -Role 'Application Mail.Read' -CustomResourceScope <scope>) or an \
         application access policy (New-ApplicationAccessPolicy -AppId <appId> -PolicyScopeGroupId <group> -AccessRight RestrictAccess), \
         then remove the tenant-wide Graph permission in Entra admin center > Enterprise applications > Permissions.",
    );

    if grants.is_empty() {
        return Ok(base
            .status(FindingStatus::Pass)
            .current_value("No service principal holds mailbox application permissions on Microsoft Graph or Exchange Online")
            .build());
    }

    let describe =
        |g: &MailboxAppGrant| format!("{} ({})", g.display_name, g.permissions.join(", "));
    let app_ids = principal_app_ids(graph, &grants).await?;
    let access_policies = exo.get("Get-ApplicationAccessPolicy", None).await;
    let role_assignments = exo
        .get(
            "Get-ManagementRoleAssignment",
            Some(json!({"RoleAssigneeType": "ServicePrincipal"})),
        )
        .await;
    let exo_sps = exo
        .get("Get-ServicePrincipal", None)
        .await
        .unwrap_or_default();

    let (policies, assignments) = match (access_policies, role_assignments) {
        (Err(e1), Err(e2)) => {
            let names: Vec<String> = grants.iter().map(describe).collect();
            return Ok(base
                .status(FindingStatus::Unknown)
                .current_value(format!(
                    "{} application(s) hold mailbox application permissions ({}) but the Exchange scoping could not be read: {}; {}",
                    grants.len(),
                    list_preview(&names, 5),
                    e1,
                    e2
                ))
                .affected_resources(names)
                .build());
        }
        (p, a) => (p.unwrap_or_default(), a.unwrap_or_default()),
    };

    let scoped = scoped_app_ids(&policies, &assignments, &exo_sps);
    let unscoped = unscoped_grants(&grants, &app_ids, &scoped);
    let names: Vec<String> = unscoped.iter().map(|g| describe(g)).collect();
    let mut f = base;
    if names.is_empty() {
        f = f.status(FindingStatus::Pass).current_value(format!(
            "{} application(s) hold mailbox application permissions; all are scoped by an application access policy or RBAC for Applications",
            grants.len()
        ));
    } else {
        f = f
            .status(FindingStatus::Fail)
            .current_value(format!(
                "{} of {} application(s) can read or send from every mailbox without a scope: {}",
                names.len(),
                grants.len(),
                list_preview(&names, 10)
            ))
            .affected_resources(names);
    }
    Ok(f.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_sp() -> Value {
        json!({"id": "graph-sp", "appId": GRAPH_APP_ID, "appRoles": [
            {"id": "r-mail", "value": "Mail.ReadWrite"},
            {"id": "r-user", "value": "User.Read.All"},
            {"id": "r-send", "value": "Mail.Send"}
        ]})
    }

    #[test]
    fn grants_filter_to_mailbox_permissions_and_group_by_principal() {
        let assignments = vec![
            json!({"principalId": "sp1", "principalDisplayName": "Backup", "principalType": "ServicePrincipal", "appRoleId": "r-mail"}),
            json!({"principalId": "sp1", "principalDisplayName": "Backup", "principalType": "ServicePrincipal", "appRoleId": "r-send"}),
            json!({"principalId": "sp2", "principalDisplayName": "HR", "principalType": "ServicePrincipal", "appRoleId": "r-user"}),
        ];
        let grants = mailbox_app_grants(&graph_sp(), &assignments);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].permissions, vec!["Mail.ReadWrite", "Mail.Send"]);
    }

    #[test]
    fn scoping_via_access_policy_or_rbac_assignment() {
        let aaps = vec![
            json!({"AppId": "APP-A", "AccessRight": "RestrictAccess"}),
            json!({"AppId": "app-x", "AccessRight": "DenyAccess"}),
        ];
        let assignments = vec![
            json!({"RoleAssigneeType": "ServicePrincipal", "RoleAssignee": "Scoped App", "CustomResourceScope": "Finance"}),
        ];
        let sps = vec![json!({"DisplayName": "Scoped App", "AppId": "app-b", "ObjectId": "obj-b"})];
        let scoped = scoped_app_ids(&aaps, &assignments, &sps);
        assert!(scoped.contains("app-a"));
        assert!(scoped.contains("app-b"));
        assert!(!scoped.contains("app-x"));

        let grants = vec![
            MailboxAppGrant {
                principal_id: "sp1".into(),
                display_name: "A".into(),
                permissions: vec!["Mail.Read".into()],
            },
            MailboxAppGrant {
                principal_id: "sp2".into(),
                display_name: "C".into(),
                permissions: vec!["Mail.Send".into()],
            },
        ];
        let mut app_ids = BTreeMap::new();
        app_ids.insert("sp1".to_string(), "app-a".to_string());
        app_ids.insert("sp2".to_string(), "app-c".to_string());
        let unscoped = unscoped_grants(&grants, &app_ids, &scoped);
        assert_eq!(unscoped.len(), 1);
        assert_eq!(unscoped[0].display_name, "C");
    }

    #[test]
    fn mailbox_permission_matching() {
        assert!(is_mailbox_permission("Mail.Read"));
        assert!(is_mailbox_permission("full_access_as_app"));
        assert!(is_mailbox_permission("MailboxSettings.ReadWrite"));
        assert!(!is_mailbox_permission("User.Read.All"));
        assert!(!is_mailbox_permission("Exchange.ManageAsApp"));
    }
}
