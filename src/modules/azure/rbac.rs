//! AZ-RBAC-001 / AZ-RBAC-002: standing Owner and User Access Administrator assignments.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde_json::{json, Value};

use super::{check, eq_ci, str_at, summarise, Ctx};
use crate::assessment::finding::{Finding, FindingStatus};

pub const OWNER_ROLE_ID: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
pub const UAA_ROLE_ID: &str = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";

/// Up to this many distinct users with standing Owner/UAA still pass (documented break-glass accounts).
const BREAK_GLASS_ALLOWANCE: usize = 2;

const ASSIGNMENTS_KQL: &str = "authorizationresources \
| where type =~ 'microsoft.authorization/roleassignments' \
| extend roleDefinitionId = tolower(tostring(properties.roleDefinitionId)), \
principalId = tostring(properties.principalId), principalType = tostring(properties.principalType), \
scope = tolower(tostring(properties.scope)) \
| where roleDefinitionId endswith '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' \
or roleDefinitionId endswith '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' \
| where (scope startswith '/subscriptions/' and scope !contains '/resourcegroups/') \
or scope startswith '/providers/microsoft.management/managementgroups/' \
| project id, principalId, principalType, roleDefinitionId, scope";

/// PIM activations and time-bound assignments surface as ordinary role assignments while active;
/// this query identifies them so they are not counted as standing access.
const ACTIVATED_KQL: &str = "authorizationresources \
| where type =~ 'microsoft.authorization/roleassignmentschedules' \
| where isnotnull(properties.endDateTime) or tostring(properties.assignmentType) =~ 'Activated' \
| project principalId = tostring(properties.principalId), \
roleDefinitionId = tolower(tostring(properties.roleDefinitionId)), scope = tolower(tostring(properties.scope))";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StandingAssignment {
    pub principal_id: String,
    pub principal_type: String,
    pub role: &'static str,
    pub scope: String,
}

pub(crate) fn role_label(role_definition_id: &str) -> Option<&'static str> {
    let lower = role_definition_id.to_ascii_lowercase();
    if lower.ends_with(OWNER_ROLE_ID) {
        Some("Owner")
    } else if lower.ends_with(UAA_ROLE_ID) {
        Some("User Access Administrator")
    } else {
        None
    }
}

fn key(v: &Value) -> (String, String, String) {
    (
        str_at(v, "principalId").to_string(),
        str_at(v, "roleDefinitionId").to_ascii_lowercase(),
        str_at(v, "scope").to_ascii_lowercase(),
    )
}

/// Owner/UAA assignments to users at subscription or management-group scope that are not PIM
/// activations or time-bound.
pub(crate) fn standing_user_assignments(
    assignments: &[Value],
    activated: &[Value],
) -> Vec<StandingAssignment> {
    let activated: BTreeSet<_> = activated.iter().map(key).collect();
    assignments
        .iter()
        .filter(|a| eq_ci(str_at(a, "principalType"), "User"))
        .filter(|a| !activated.contains(&key(a)))
        .filter_map(|a| {
            Some(StandingAssignment {
                principal_id: str_at(a, "principalId").to_string(),
                principal_type: str_at(a, "principalType").to_string(),
                role: role_label(str_at(a, "roleDefinitionId"))?,
                scope: str_at(a, "scope").to_string(),
            })
        })
        .collect()
}

pub(crate) fn distinct_principals(standing: &[StandingAssignment]) -> Vec<String> {
    let set: BTreeSet<&str> = standing.iter().map(|s| s.principal_id.as_str()).collect();
    set.into_iter().map(String::from).collect()
}

pub(crate) async fn standing_privileged_users(ctx: &Ctx<'_>) -> Result<Finding> {
    let assignments = ctx.resource_graph(ASSIGNMENTS_KQL).await?;
    // Best effort: tenants without PIM for Azure resources (or an older Resource Graph schema) may not
    // expose roleassignmentschedules; then nothing is excluded and the note says so.
    let (activated, pim_visible) = match ctx.resource_graph(ACTIVATED_KQL).await {
        Ok(rows) => (rows, true),
        Err(e) => {
            tracing::debug!("roleassignmentschedules not readable: {e}");
            (Vec::new(), false)
        }
    };
    let standing = standing_user_assignments(&assignments, &activated);
    let principals = distinct_principals(&standing);
    let names = ctx.resolve_principals(&principals).await;
    let non_user = assignments
        .iter()
        .filter(|a| !eq_ci(str_at(a, "principalType"), "User"))
        .count();

    let labels: Vec<String> = standing
        .iter()
        .map(|s| {
            format!(
                "{} as {} at {}",
                names
                    .get(&s.principal_id)
                    .cloned()
                    .unwrap_or_else(|| s.principal_id.clone()),
                s.role,
                s.scope
            )
        })
        .collect();

    let status = if principals.len() <= BREAK_GLASS_ALLOWANCE {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };
    let mut current = if standing.is_empty() {
        "No user holds a permanent Owner or User Access Administrator assignment at subscription or management-group scope.".to_string()
    } else {
        format!(
            "{} user(s) hold {} permanent Owner/User Access Administrator assignment(s): {}.",
            principals.len(),
            standing.len(),
            summarise(&labels, 8)
        )
    };
    if status == FindingStatus::Pass && !standing.is_empty() {
        current.push_str(
            " Within the break-glass allowance; confirm these are documented emergency accounts.",
        );
    }
    if !pim_visible {
        current.push_str(
            " PIM activation data was not readable, so activated assignments may be counted.",
        );
    }
    current.push_str(&format!(
        " {non_user} assignment(s) to groups or service principals are not counted; review them separately."
    ));

    Ok(check(
        ctx.registry,
        "AZ-RBAC-001",
        "AZURE",
        "Azure RBAC",
        "Permanent Owner / User Access Administrator for users",
        "Users should hold Owner and User Access Administrator at management-group and subscription scope only as PIM-eligible \
assignments. Standing assignments let one compromised account take over workloads, data and backups.",
    )
    .status(status)
    .current_value(current)
    .expected_value(format!(
        "No permanent Owner/UAA user assignments beyond at most {BREAK_GLASS_ALLOWANCE} documented break-glass accounts"
    ))
    .remediation(
        "Convert human Owner and User Access Administrator assignments to PIM-eligible with MFA and approval, scope automation \
identities to resource groups, and keep only documented break-glass accounts as permanent.",
    )
    .affected_resources(labels)
    .details(json!({
        "standing": standing.iter().map(|s| json!({
            "principalId": s.principal_id, "principalType": s.principal_type, "role": s.role, "scope": s.scope,
            "displayName": names.get(&s.principal_id),
        })).collect::<Vec<_>>(),
        "nonUserAssignments": non_user,
        "pimSchedulesReadable": pim_visible,
    }))
    .build())
}

/// Root-scope (`/`) User Access Administrator assignments from `atScope()` at the tenant root.
pub(crate) fn root_uaa_assignments(items: &[Value]) -> Vec<(String, String)> {
    items
        .iter()
        .filter(|a| a["properties"]["scope"].as_str() == Some("/"))
        .filter(|a| {
            role_label(str_at(&a["properties"], "roleDefinitionId"))
                == Some("User Access Administrator")
        })
        .map(|a| {
            (
                str_at(&a["properties"], "principalId").to_string(),
                str_at(&a["properties"], "principalType").to_string(),
            )
        })
        .collect()
}

pub(crate) async fn root_scope_uaa(ctx: &Ctx<'_>) -> Result<Finding> {
    let items = ctx
        .arm_get_all(
            "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()",
        )
        .await?;
    let root = root_uaa_assignments(&items);
    let ids: Vec<String> = root.iter().map(|(id, _)| id.clone()).collect();
    let names: BTreeMap<String, String> = ctx.resolve_principals(&ids).await;
    let labels: Vec<String> = root
        .iter()
        .map(|(id, kind)| {
            format!(
                "{} ({})",
                names.get(id).cloned().unwrap_or_else(|| id.clone()),
                if kind.is_empty() {
                    "unknown type"
                } else {
                    kind
                }
            )
        })
        .collect();
    let status = if root.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };
    Ok(check(
        ctx.registry,
        "AZ-RBAC-002",
        "AZURE",
        "Azure RBAC",
        "User Access Administrator at root scope",
        "A Global Administrator who elevates access to Azure resources receives User Access Administrator at the tenant root \
scope `/`. Left in place, it grants control over every subscription and is a common persistence point.",
    )
    .status(status)
    .current_value(if root.is_empty() {
        "No User Access Administrator assignment exists at root scope '/'.".to_string()
    } else {
        format!(
            "{} principal(s) hold User Access Administrator at root scope '/': {}",
            root.len(),
            summarise(&labels, 10)
        )
    })
    .expected_value("No User Access Administrator assignments at root scope '/'")
    .remediation(
        "Remove elevated access: in Entra ID > Properties turn off 'Access management for Azure resources', or delete the \
root-scope assignment with `az role assignment delete --scope / --assignee <id> --role 'User Access Administrator'`.",
    )
    .affected_resources(labels)
    .details(json!({ "rootScopeAssignments": root.iter().map(|(id, kind)| json!({"principalId": id, "principalType": kind})).collect::<Vec<_>>() }))
    .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignment(principal: &str, kind: &str, role: &str, scope: &str) -> Value {
        json!({
            "id": format!("{scope}/providers/microsoft.authorization/roleassignments/{principal}-{role}"),
            "principalId": principal,
            "principalType": kind,
            "roleDefinitionId": format!("/providers/microsoft.authorization/roledefinitions/{role}"),
            "scope": scope,
        })
    }

    #[test]
    fn users_only_and_pim_activations_excluded() {
        let sub = "/subscriptions/00000000-0000-0000-0000-000000000001";
        let rows = vec![
            assignment("u1", "User", OWNER_ROLE_ID, sub),
            assignment("u2", "User", UAA_ROLE_ID, sub),
            assignment("sp1", "ServicePrincipal", OWNER_ROLE_ID, sub),
            assignment("g1", "Group", OWNER_ROLE_ID, sub),
        ];
        let activated = vec![json!({
            "principalId": "u2",
            "roleDefinitionId": format!("/providers/microsoft.authorization/roledefinitions/{UAA_ROLE_ID}"),
            "scope": sub,
        })];
        let standing = standing_user_assignments(&rows, &activated);
        assert_eq!(standing.len(), 1);
        assert_eq!(standing[0].principal_id, "u1");
        assert_eq!(standing[0].role, "Owner");
        assert_eq!(distinct_principals(&standing), vec!["u1".to_string()]);
    }

    #[test]
    fn distinct_principals_dedupes_multiple_scopes() {
        let rows = vec![
            assignment("u1", "User", OWNER_ROLE_ID, "/subscriptions/a"),
            assignment("u1", "User", OWNER_ROLE_ID, "/subscriptions/b"),
            assignment(
                "u3",
                "User",
                UAA_ROLE_ID,
                "/providers/microsoft.management/managementgroups/root",
            ),
        ];
        let standing = standing_user_assignments(&rows, &[]);
        assert_eq!(standing.len(), 3);
        assert_eq!(distinct_principals(&standing).len(), 2);
    }

    #[test]
    fn root_scope_uaa_filtered() {
        let items = vec![
            json!({"properties": {"scope": "/", "principalId": "ga", "principalType": "User",
                "roleDefinitionId": format!("/providers/Microsoft.Authorization/roleDefinitions/{UAA_ROLE_ID}")}}),
            json!({"properties": {"scope": "/", "principalId": "x", "principalType": "User",
                "roleDefinitionId": format!("/providers/Microsoft.Authorization/roleDefinitions/{OWNER_ROLE_ID}")}}),
            json!({"properties": {"scope": "/subscriptions/a", "principalId": "y", "principalType": "User",
                "roleDefinitionId": format!("/providers/Microsoft.Authorization/roleDefinitions/{UAA_ROLE_ID}")}}),
        ];
        let root = root_uaa_assignments(&items);
        assert_eq!(root, vec![("ga".to_string(), "User".to_string())]);
    }
}
