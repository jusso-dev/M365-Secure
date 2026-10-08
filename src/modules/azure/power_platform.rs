//! PP-GOVERNANCE-001 (crownguard MS-AI-004): Power Platform rule-based data policies through the
//! Power Platform API. Classic DLP policies (api.bap.microsoft.com) have no catalogued read and are not
//! inspected.

use anyhow::Result;
use serde_json::{json, Value};

use super::{check, str_at, summarise};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::auth::Resource;
use crate::junction::JunctionGateway;

pub(crate) fn policy_names(policies: &[Value]) -> Vec<String> {
    policies
        .iter()
        .map(|p| {
            let name = str_at(p, "displayName");
            if name.is_empty() {
                str_at(p, "name").to_string()
            } else {
                name.to_string()
            }
        })
        .filter(|n| !n.is_empty())
        .collect()
}

pub(crate) fn evaluate(policies: &[Value]) -> FindingStatus {
    if policies.is_empty() {
        FindingStatus::Warning
    } else {
        FindingStatus::Pass
    }
}

pub(crate) async fn governance(
    jx: &JunctionGateway,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policies = jx
        .list(
            Resource::PowerPlatform,
            "power_platform.governance.rule_based_policies.list_rule_based_policies",
            json!({ "parameters": {} }),
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "{e}. The signed-in app needs the Power Platform API (api.powerplatform.com) delegated permission and the user \
needs Power Platform administrator."
            )
        })?;
    let names = policy_names(&policies);
    let status = evaluate(&policies);
    Ok(check(
        registry,
        "PP-GOVERNANCE-001",
        "POWERPLATFORM",
        "Power Platform governance",
        "Rule-based data policies",
        "Power Platform data policies should separate business from non-business connectors and block HTTP and unapproved \
connectors in the default and production environments, so Copilot Studio agents and flows cannot move data to unapproved services.",
    )
    .status(status)
    .current_value(format!(
        "{} rule-based data policy(ies){}{}. Classic DLP policies (api.bap.microsoft.com) are not read; if governance is \
classic-only, record it as attestation. Agent sharing limits and the agent registry review remain attestation.",
        policies.len(),
        if names.is_empty() { "" } else { ": " },
        summarise(&names, 5)
    ))
    .expected_value("At least one rule-based data policy covering the default environment")
    .remediation(
        "In the Power Platform admin center create a data policy (rule-based) that classifies connectors as business or \
non-business, blocks the HTTP and custom connectors in the default environment, and enable Managed Environments for production.",
    )
    .details(json!({ "ruleBasedPolicies": policies.len(), "names": names }))
    .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_status() {
        let policies = vec![
            json!({"displayName": "Default tenant policy", "name": "p1"}),
            json!({"name": "p2"}),
            json!({}),
        ];
        assert_eq!(policy_names(&policies), vec!["Default tenant policy", "p2"]);
        assert_eq!(evaluate(&policies), FindingStatus::Pass);
        assert_eq!(evaluate(&[]), FindingStatus::Warning);
    }
}
