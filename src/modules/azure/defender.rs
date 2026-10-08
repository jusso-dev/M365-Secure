//! AZ-DEFENDER-001 / AZ-DEFENDER-002: Defender for Cloud plans, secure score and open high-severity
//! recommendations.
//!
//! Plans and assessments come from the Resource Graph `securityresources` table: one query covers every
//! readable subscription, and assessments there carry `metadata.severity`, which the per-scope
//! `Microsoft.Security/assessments` list omits without `$expand`.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde_json::{json, Value};

use super::{check, eq_ci, str_at, summarise, Ctx, Subscription};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::auth::Resource;
use crate::junction::JunctionGateway;

const PRICINGS_KQL: &str = "securityresources \
| where type =~ 'microsoft.security/pricings' \
| project subscriptionId, plan = name, tier = tostring(properties.pricingTier)";

const INVENTORY_KQL: &str = "resources \
| where type in~ ('microsoft.compute/virtualmachines', 'microsoft.hybridcompute/machines', \
'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.keyvault/vaults', \
'microsoft.containerservice/managedclusters', 'microsoft.containerregistry/registries') \
| summarize n = count() by subscriptionId, type = tolower(type)";

const UNHEALTHY_HIGH_KQL: &str = "securityresources \
| where type =~ 'microsoft.security/assessments' \
| where tostring(properties.status.code) =~ 'Unhealthy' and tostring(properties.metadata.severity) =~ 'High' \
| summarize unhealthy = count() by subscriptionId";

/// Defender plan that protects a resource type. `Arm` is relevant to every subscription.
fn plan_for_type(resource_type: &str) -> Option<&'static str> {
    Some(match resource_type.to_ascii_lowercase().as_str() {
        "microsoft.compute/virtualmachines" | "microsoft.hybridcompute/machines" => {
            "VirtualMachines"
        }
        "microsoft.storage/storageaccounts" => "StorageAccounts",
        "microsoft.sql/servers" => "SqlServers",
        "microsoft.keyvault/vaults" => "KeyVaults",
        "microsoft.containerservice/managedclusters" | "microsoft.containerregistry/registries" => {
            "Containers"
        }
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubscriptionPlans {
    pub subscription_id: String,
    pub standard: Vec<String>,
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanReport {
    pub per_subscription: Vec<SubscriptionPlans>,
    pub status: FindingStatus,
}

/// Which relevant plans are Standard per subscription.
pub(crate) fn evaluate_plans(
    pricings: &[Value],
    inventory: &[Value],
    subscriptions: &[Subscription],
) -> PlanReport {
    let mut relevant: BTreeMap<&str, BTreeSet<&'static str>> = subscriptions
        .iter()
        .map(|s| (s.id.as_str(), BTreeSet::from(["Arm"])))
        .collect();
    for row in inventory {
        if row["n"].as_i64().unwrap_or(0) <= 0 {
            continue;
        }
        if let (Some(set), Some(plan)) = (
            relevant.get_mut(str_at(row, "subscriptionId")),
            plan_for_type(str_at(row, "type")),
        ) {
            set.insert(plan);
        }
    }
    let mut standard: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for row in pricings {
        if eq_ci(str_at(row, "tier"), "Standard") {
            standard
                .entry(str_at(row, "subscriptionId"))
                .or_default()
                .insert(str_at(row, "plan").to_ascii_lowercase());
        }
    }
    let per_subscription: Vec<SubscriptionPlans> = relevant
        .iter()
        .map(|(sub, plans)| {
            let on = standard.get(sub).cloned().unwrap_or_default();
            let (standard, missing): (Vec<_>, Vec<_>) = plans
                .iter()
                .map(|p| p.to_string())
                .partition(|p| on.contains(&p.to_ascii_lowercase()));
            SubscriptionPlans {
                subscription_id: sub.to_string(),
                standard,
                missing,
            }
        })
        .collect();
    let any_standard = per_subscription.iter().any(|s| !s.standard.is_empty());
    let all_standard = per_subscription.iter().all(|s| s.missing.is_empty());
    let status = if all_standard {
        FindingStatus::Pass
    } else if any_standard {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };
    PlanReport {
        per_subscription,
        status,
    }
}

pub(crate) async fn plans(ctx: &Ctx<'_>) -> Result<Finding> {
    let pricings = ctx.resource_graph(PRICINGS_KQL).await?;
    let inventory = ctx.resource_graph(INVENTORY_KQL).await?;
    let report = evaluate_plans(&pricings, &inventory, &ctx.subscriptions);
    let name_of = |id: &str| {
        ctx.subscriptions
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| id.to_string())
    };
    let gaps: Vec<String> = report
        .per_subscription
        .iter()
        .filter(|s| !s.missing.is_empty())
        .map(|s| format!("{}: {}", name_of(&s.subscription_id), s.missing.join("/")))
        .collect();
    let current = if gaps.is_empty() {
        format!(
            "Every relevant Defender plan is Standard across {} subscription(s).",
            report.per_subscription.len()
        )
    } else {
        format!(
            "{} of {} subscription(s) have relevant Defender plans on the Free tier or missing: {}",
            gaps.len(),
            report.per_subscription.len(),
            summarise(&gaps, 8)
        )
    };
    Ok(check(
        ctx.registry,
        "AZ-DEFENDER-001",
        "AZURE",
        "Defender for Cloud",
        "Defender plans on subscriptions with matching resources",
        "Defender for Cloud plans (Servers, Storage, SQL, Key Vault, Containers, Resource Manager) should be on the Standard tier \
wherever the subscription holds resources of that type. Resource Manager is relevant to every subscription.",
    )
    .status(report.status)
    .current_value(current)
    .expected_value("pricingTier = Standard for every plan whose resource type exists in the subscription")
    .remediation(
        "Enable the Defender plans through Azure Policy at management-group scope (Defender for Cloud > Environment settings), \
starting with Resource Manager, Servers, Storage, SQL and Key Vault for production subscriptions.",
    )
    .affected_resources(gaps)
    .details(json!({
        "subscriptions": report.per_subscription.iter().map(|s| json!({
            "subscriptionId": s.subscription_id, "name": name_of(&s.subscription_id),
            "standard": s.standard, "missing": s.missing,
        })).collect::<Vec<_>>(),
    }))
    .build())
}

/// Secure score percentage from a `secureScores` list response (the `ascore` entry).
pub(crate) fn ascore_percentage(items: &[Value]) -> Option<f64> {
    items
        .iter()
        .find(|i| eq_ci(str_at(i, "name"), "ascore"))
        .and_then(|i| {
            let score = &i["properties"]["score"];
            score["percentage"].as_f64().or_else(|| {
                let current = score["current"].as_f64()?;
                let max = score["max"].as_f64()?;
                (max > 0.0).then(|| current / max)
            })
        })
}

pub(crate) fn unhealthy_high_by_subscription(rows: &[Value]) -> BTreeMap<String, i64> {
    rows.iter()
        .filter_map(|r| {
            let sub = str_at(r, "subscriptionId");
            (!sub.is_empty()).then(|| (sub.to_string(), r["unhealthy"].as_i64().unwrap_or(0)))
        })
        .collect()
}

pub(crate) async fn posture(ctx: &Ctx<'_>) -> Result<Finding> {
    let unhealthy = unhealthy_high_by_subscription(&ctx.resource_graph(UNHEALTHY_HIGH_KQL).await?);
    let mut scores: Vec<Value> = Vec::new();
    let mut score_errors = 0usize;
    for sub in &ctx.subscriptions {
        match ctx
            .jx
            .list(
                Resource::AzureResourceManager,
                "defender.cloud.secure_scores.list",
                JunctionGateway::params(&[("subscriptionId", &sub.id)]),
            )
            .await
        {
            Ok(items) => scores.push(json!({
                "subscriptionId": sub.id, "name": sub.name,
                "securescorePercentage": ascore_percentage(&items).map(|p| (p * 100.0).round()),
                "unhealthyHigh": unhealthy.get(&sub.id).copied().unwrap_or(0),
            })),
            Err(e) => {
                tracing::debug!("secure score for {} unavailable: {e}", sub.id);
                score_errors += 1;
                scores.push(json!({
                    "subscriptionId": sub.id, "name": sub.name, "securescorePercentage": Value::Null,
                    "unhealthyHigh": unhealthy.get(&sub.id).copied().unwrap_or(0),
                }));
            }
        }
    }
    let total_unhealthy: i64 = unhealthy.values().sum();
    let score_text: Vec<String> = scores
        .iter()
        .map(|s| {
            format!(
                "{} {}{}",
                str_at(s, "name"),
                s["securescorePercentage"]
                    .as_f64()
                    .map(|p| format!("{p:.0}%"))
                    .unwrap_or_else(|| "score n/a".to_string()),
                match s["unhealthyHigh"].as_i64().unwrap_or(0) {
                    0 => String::new(),
                    n => format!(" ({n} unhealthy High)"),
                }
            )
        })
        .collect();
    let status = if total_unhealthy == 0 {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };
    let mut current = format!(
        "{total_unhealthy} unhealthy High-severity recommendation(s) across {} subscription(s). Secure score: {}.",
        ctx.subscriptions.len(),
        summarise(&score_text, 8)
    );
    if score_errors > 0 {
        current.push_str(&format!(
            " Secure score unavailable for {score_errors} subscription(s) (Defender for Cloud may not be initialised there)."
        ));
    }
    Ok(check(
        ctx.registry,
        "AZ-DEFENDER-002",
        "AZURE",
        "Defender for Cloud",
        "Secure score and unhealthy high-severity recommendations",
        "Defender for Cloud secure score per subscription and the count of High-severity recommendations still in the Unhealthy \
state. Open high-severity findings are the misconfigurations attackers find first.",
    )
    .status(status)
    .current_value(current)
    .expected_value("No High-severity recommendations in the Unhealthy state; secure score trending up")
    .remediation(
        "In Defender for Cloud > Recommendations filter on High severity, assign owners and due dates, and remediate or exempt \
with justification. Track the secure score per subscription.",
    )
    .details(json!({ "subscriptions": scores }))
    .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subs() -> Vec<Subscription> {
        vec![
            Subscription {
                id: "s1".into(),
                name: "Prod".into(),
                state: "Enabled".into(),
            },
            Subscription {
                id: "s2".into(),
                name: "Dev".into(),
                state: "Enabled".into(),
            },
        ]
    }

    #[test]
    fn plans_relevant_only_where_resources_exist() {
        let pricings = vec![
            json!({"subscriptionId": "s1", "plan": "VirtualMachines", "tier": "Standard"}),
            json!({"subscriptionId": "s1", "plan": "Arm", "tier": "Standard"}),
            json!({"subscriptionId": "s1", "plan": "KeyVaults", "tier": "Free"}),
            json!({"subscriptionId": "s2", "plan": "Arm", "tier": "Standard"}),
        ];
        let inventory = vec![
            json!({"subscriptionId": "s1", "type": "microsoft.compute/virtualmachines", "n": 3}),
            json!({"subscriptionId": "s1", "type": "microsoft.keyvault/vaults", "n": 1}),
            json!({"subscriptionId": "s2", "type": "microsoft.storage/storageaccounts", "n": 0}),
        ];
        let report = evaluate_plans(&pricings, &inventory, &subs());
        assert_eq!(report.status, FindingStatus::Warning);
        let s1 = report
            .per_subscription
            .iter()
            .find(|s| s.subscription_id == "s1")
            .unwrap();
        assert_eq!(s1.missing, vec!["KeyVaults".to_string()]);
        let s2 = report
            .per_subscription
            .iter()
            .find(|s| s.subscription_id == "s2")
            .unwrap();
        assert!(s2.missing.is_empty());
    }

    #[test]
    fn plans_all_standard_passes_and_none_fails() {
        let pricings = vec![
            json!({"subscriptionId": "s1", "plan": "Arm", "tier": "Standard"}),
            json!({"subscriptionId": "s2", "plan": "Arm", "tier": "Standard"}),
        ];
        assert_eq!(
            evaluate_plans(&pricings, &[], &subs()).status,
            FindingStatus::Pass
        );
        assert_eq!(
            evaluate_plans(&[], &[], &subs()).status,
            FindingStatus::Fail
        );
    }

    #[test]
    fn ascore_reads_percentage_or_ratio() {
        let items = vec![
            json!({"name": "ascore", "properties": {"score": {"current": 30.0, "max": 60.0}}}),
        ];
        assert_eq!(ascore_percentage(&items), Some(0.5));
        let items = vec![json!({"name": "ascore", "properties": {"score": {"percentage": 0.42}}})];
        assert_eq!(ascore_percentage(&items), Some(0.42));
        assert_eq!(ascore_percentage(&[]), None);
    }
}
