//! DEFENDER-SECURESCORE-001: informational Secure Score summary. Never Pass or Fail; the
//! individual policy checks carry the verdicts.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use crate::modules::exchange::exo::{finding, str_of};

/// Score and maximum per control category from the latest `secureScore.controlScores`.
pub fn category_scores(score: &Value) -> BTreeMap<String, (f64, usize)> {
    let mut out: BTreeMap<String, (f64, usize)> = BTreeMap::new();
    if let Some(controls) = score["controlScores"].as_array() {
        for c in controls {
            let category = str_of(c, "controlCategory").unwrap_or("Other").to_string();
            let points = c["score"].as_f64().unwrap_or(0.0);
            let entry = out.entry(category).or_insert((0.0, 0));
            entry.0 += points;
            entry.1 += 1;
        }
    }
    out
}

pub async fn check_secure_score(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let resp = graph.get_json("/v1.0/security/secureScores?$top=1").await?;
    let latest = resp["value"]
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow::anyhow!("secureScores returned no entries"))?;
    let current = latest["currentScore"].as_f64().unwrap_or(0.0);
    let max = latest["maxScore"].as_f64().unwrap_or(0.0);
    let pct = if max > 0.0 {
        current / max * 100.0
    } else {
        0.0
    };
    let categories = category_scores(latest);
    let breakdown: Vec<String> = categories
        .iter()
        .map(|(cat, (points, n))| format!("{} {:.0} pts over {} controls", cat, points, n))
        .collect();
    Ok(finding(
        registry,
        "DEFENDER-SECURESCORE-001",
        "Security",
        "Microsoft Defender",
        "Microsoft Secure Score",
        "Informational: the tenant's Microsoft Secure Score and its spread across control categories",
    )
    .status(FindingStatus::Info)
    .current_value(format!(
        "{:.1} of {:.1} ({:.0}%) as of {}{}",
        current,
        max,
        pct,
        str_of(latest, "createdDateTime").unwrap_or("unknown date"),
        if breakdown.is_empty() {
            String::new()
        } else {
            format!("; {}", breakdown.join(", "))
        }
    ))
    .expected_value("Informational; use the individual policy checks for pass/fail")
    .remediation("Defender portal > Exposure management > Secure Score > Recommended actions lists the remaining improvement actions.")
    .details(json!({
        "currentScore": current,
        "maxScore": max,
        "categories": categories.iter().map(|(k, (p, n))| json!({"category": k, "score": p, "controls": n})).collect::<Vec<_>>(),
    }))
    .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_sum_control_scores() {
        let score = json!({"controlScores": [
            {"controlCategory": "Identity", "controlName": "MFA", "score": 10.0},
            {"controlCategory": "Identity", "controlName": "PIM", "score": 5.0},
            {"controlCategory": "Data", "controlName": "DLP", "score": 2.5}
        ]});
        let cats = category_scores(&score);
        assert_eq!(cats["Identity"], (15.0, 2));
        assert_eq!(cats["Data"], (2.5, 1));
    }
}
