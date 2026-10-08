//! MDI-SENSOR-001: Defender for Identity sensors are deployed and healthy.

use anyhow::Result;
use serde_json::Value;

use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use crate::modules::exchange::exo::{finding, list_preview, str_of};

const ID: &str = "MDI-SENSOR-001";
const CATEGORY: &str = "Security";
const SECTION: &str = "Defender for Identity";
const SETTING: &str = "Sensor Health";
const DESCRIPTION: &str = "Defender for Identity sensors are installed on identity servers, healthy, and have no open high-severity health issues";

#[derive(Debug, PartialEq, Eq)]
pub struct SensorEval {
    pub status: FindingStatus,
    pub summary: String,
    pub affected: Vec<String>,
}

pub fn evaluate_sensors(sensors: &[Value], open_issues: &[Value]) -> SensorEval {
    if sensors.is_empty() {
        return SensorEval {
            status: FindingStatus::Fail,
            summary: "Defender for Identity is licensed but no sensors are registered".to_string(),
            affected: vec![],
        };
    }
    let unhealthy: Vec<String> = sensors
        .iter()
        .filter(|s| !str_of(s, "healthStatus").is_some_and(|h| h.eq_ignore_ascii_case("healthy")))
        .map(|s| {
            format!(
                "{} ({})",
                str_of(s, "displayName").unwrap_or("(unnamed)"),
                str_of(s, "healthStatus").unwrap_or("unknown")
            )
        })
        .collect();
    let high: Vec<String> = open_issues
        .iter()
        .filter(|i| str_of(i, "severity").is_some_and(|s| s.eq_ignore_ascii_case("high")))
        .map(|i| {
            str_of(i, "displayName")
                .unwrap_or("(unnamed issue)")
                .to_string()
        })
        .collect();
    let mut affected = unhealthy.clone();
    affected.extend(high.iter().cloned());
    let status = if unhealthy.is_empty() && high.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };
    let summary = format!(
        "{} sensor(s), {} unhealthy{}; {} open health issue(s), {} high severity{}",
        sensors.len(),
        unhealthy.len(),
        if unhealthy.is_empty() {
            String::new()
        } else {
            format!(" ({})", list_preview(&unhealthy, 5))
        },
        open_issues.len(),
        high.len(),
        if high.is_empty() {
            String::new()
        } else {
            format!(" ({})", list_preview(&high, 5))
        }
    );
    SensorEval {
        status,
        summary,
        affected,
    }
}

pub async fn check_sensors(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let base = finding(registry, ID, CATEGORY, SECTION, SETTING, DESCRIPTION)
        .expected_value("Every sensor healthStatus = healthy and no open high-severity health issue")
        .remediation(
            "Defender portal > Settings > Identities > Sensors: install sensors on all domain controllers, AD FS, AD CS and \
             Entra Connect servers, then resolve the items under Health issues.",
        );
    if !tenant.has_service_plan("ATA") {
        return Ok(base
            .status(FindingStatus::NotLicensed)
            .current_value("Defender for Identity service plan (ATA) not detected")
            .build());
    }
    let sensors: Vec<Value> = graph
        .get_all::<Value>("/beta/security/identities/sensors")
        .await?;
    let issues: Vec<Value> = graph
        .get_all::<Value>("/beta/security/identities/healthIssues?$filter=status eq 'open'")
        .await?;
    let eval = evaluate_sensors(&sensors, &issues);
    let mut f = base.status(eval.status).current_value(eval.summary);
    if !eval.affected.is_empty() {
        f = f.affected_resources(eval.affected);
    }
    Ok(f.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sensor_evaluation() {
        assert_eq!(evaluate_sensors(&[], &[]).status, FindingStatus::Fail);
        let healthy = vec![json!({"displayName": "DC01", "healthStatus": "healthy"})];
        assert_eq!(evaluate_sensors(&healthy, &[]).status, FindingStatus::Pass);
        let mixed = vec![
            json!({"displayName": "DC01", "healthStatus": "healthy"}),
            json!({"displayName": "DC02", "healthStatus": "notHealthyHigh"}),
        ];
        let eval = evaluate_sensors(&mixed, &[]);
        assert_eq!(eval.status, FindingStatus::Warning);
        assert_eq!(eval.affected.len(), 1);
        let issues = vec![json!({"displayName": "Sensor service stopped", "severity": "high"})];
        assert_eq!(
            evaluate_sensors(&healthy, &issues).status,
            FindingStatus::Warning
        );
        let low = vec![json!({"displayName": "Clock skew", "severity": "low"})];
        assert_eq!(evaluate_sensors(&healthy, &low).status, FindingStatus::Pass);
    }
}
