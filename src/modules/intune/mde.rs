//! Defender for Endpoint (MDE-*) via the Defender for Endpoint API. Licence gates come from the tenant's
//! service plans; consent failures from token acquisition surface as `Unknown` with the hint.

use anyhow::Result;
use serde_json::Value;

use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::FindingStatus;
use crate::auth::{CloudEnvironment, Resource};
use crate::graph::GraphClient;

use super::catalog::Outcome;

/// Service plans that include Defender for Endpoint: P2, Defender for Business, P1 (two spellings).
pub const MDE_PLANS: [&str; 4] = ["WINDEFATP", "MDE_SMB", "DEFENDER_ENDPOINT_P1", "MDE_LITE"];

/// Tamper protection in the secure configuration assessment.
const TAMPER_SCID: &str = "scid-2010";
const COVERAGE_THRESHOLD: f64 = 0.95;

pub fn licensed(tenant: &TenantInfo) -> bool {
    MDE_PLANS.iter().any(|p| tenant.has_service_plan(p))
}

fn base_url(graph: &GraphClient) -> &'static str {
    if graph.auth().cloud() == CloudEnvironment::Commercial {
        "https://api.securitycenter.microsoft.com"
    } else {
        "https://api-gcc.securitycenter.microsoft.us"
    }
}

pub struct MdeData {
    pub machines: Result<Vec<Value>>,
    /// `(compliant, total)` devices for the tamper protection configuration.
    pub tamper: Result<(usize, usize)>,
}

pub async fn collect(graph: &GraphClient) -> MdeData {
    let base = base_url(graph);
    let machines = graph
        .get_resource_all(
            Resource::DefenderForEndpoint,
            &format!("{base}/api/machines?$select=id,computerDnsName,onboardingStatus,healthStatus,osPlatform"),
        )
        .await;
    let tamper = match machines {
        // No point hunting when the API already refused us.
        Err(ref e) => Err(anyhow::anyhow!("{e}")),
        Ok(_) => tamper_protection(graph, base).await,
    };
    MdeData { machines, tamper }
}

async fn tamper_protection(graph: &GraphClient, base: &str) -> Result<(usize, usize)> {
    let query = format!(
        "DeviceTvmSecureConfigurationAssessment | where ConfigurationId == '{TAMPER_SCID}' | summarize Total=count(), Compliant=countif(IsCompliant == 1)"
    );
    let hunt = graph
        .post_resource_json(
            Resource::DefenderForEndpoint,
            &format!("{base}/api/advancedqueries/run"),
            &serde_json::json!({"Query": query}),
        )
        .await;
    match hunt {
        Ok(body) => return parse_hunt(&body),
        Err(e) => tracing::warn!(
            "advanced hunting unavailable, falling back to the assessment export: {e}"
        ),
    }
    let rows = graph
        .get_resource_all(
            Resource::DefenderForEndpoint,
            &format!("{base}/api/machines/SecureConfigurationsAssessmentByMachine"),
        )
        .await?;
    Ok(parse_assessment_rows(&rows))
}

/// `{Schema, Results:[{Total, Compliant}]}` from the summarize query.
pub fn parse_hunt(body: &Value) -> Result<(usize, usize)> {
    let row = body
        .get("Results")
        .and_then(|r| r.as_array())
        .and_then(|r| r.first())
        .ok_or_else(|| anyhow::anyhow!("advanced hunting returned no rows for {TAMPER_SCID}"))?;
    let total = row.get("Total").and_then(|t| t.as_u64()).unwrap_or(0) as usize;
    let compliant = row.get("Compliant").and_then(|t| t.as_u64()).unwrap_or(0) as usize;
    Ok((compliant, total))
}

/// Per-machine rows from `SecureConfigurationsAssessmentByMachine`, filtered to tamper protection.
pub fn parse_assessment_rows(rows: &[Value]) -> (usize, usize) {
    let tamper = rows
        .iter()
        .filter(|r| r.get("configurationId").and_then(|c| c.as_str()) == Some(TAMPER_SCID));
    let mut total = 0;
    let mut compliant = 0;
    for r in tamper {
        total += 1;
        if r.get("isCompliant")
            .and_then(|b| b.as_bool())
            .unwrap_or(false)
        {
            compliant += 1;
        }
    }
    (compliant, total)
}

/// MDE-ONBOARD-001: onboarded, active Defender machines against Intune-managed Windows, macOS and Linux devices.
pub fn onboard_001(machines: &[Value], intune_endpoints: usize) -> Outcome {
    let onboarded = machines
        .iter()
        .filter(|m| {
            m.get("onboardingStatus")
                .and_then(|s| s.as_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("Onboarded"))
        })
        .count();
    let active = machines
        .iter()
        .filter(|m| {
            m.get("onboardingStatus")
                .and_then(|s| s.as_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("Onboarded"))
                && m.get("healthStatus")
                    .and_then(|s| s.as_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("Active"))
        })
        .count();
    if intune_endpoints == 0 {
        return Ok(if onboarded == 0 {
            (
                FindingStatus::Fail,
                "No devices onboarded to Defender for Endpoint".to_string(),
            )
        } else {
            (
                FindingStatus::Warning,
                format!("{onboarded} onboarded ({active} active); no Intune-managed endpoints to compare against"),
            )
        });
    }
    let ratio = (active as f64 / intune_endpoints as f64).min(1.0);
    let current = format!(
        "{active} active of {onboarded} onboarded Defender machines; {intune_endpoints} Intune-managed endpoints ({:.0}% covered)",
        ratio * 100.0
    );
    Ok(if ratio >= COVERAGE_THRESHOLD {
        (FindingStatus::Pass, current)
    } else {
        (FindingStatus::Warning, current)
    })
}

/// MDE-TAMPER-001: tamper protection enabled on at least 95% of assessed devices.
pub fn tamper_001(compliant: usize, total: usize) -> Outcome {
    if total == 0 {
        anyhow::bail!("no devices carry a tamper protection assessment ({TAMPER_SCID}) yet");
    }
    let ratio = compliant as f64 / total as f64;
    let current = format!(
        "Tamper protection on for {compliant} of {total} devices ({:.0}%)",
        ratio * 100.0
    );
    Ok(if ratio >= COVERAGE_THRESHOLD {
        (FindingStatus::Pass, current)
    } else {
        (FindingStatus::Warning, current)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn onboarding_ratio() {
        let m = |o: &str, h: &str| json!({"onboardingStatus": o, "healthStatus": h});
        let machines = vec![
            m("Onboarded", "Active"),
            m("Onboarded", "Inactive"),
            m("CanBeOnboarded", "Active"),
        ];
        let (s, text) = onboard_001(&machines, 1).unwrap();
        assert_eq!(s, FindingStatus::Pass);
        assert!(text.contains("1 active of 2 onboarded"), "{text}");
        assert_eq!(onboard_001(&machines, 2).unwrap().0, FindingStatus::Warning);
        assert_eq!(onboard_001(&[], 0).unwrap().0, FindingStatus::Fail);
        assert_eq!(onboard_001(&machines, 0).unwrap().0, FindingStatus::Warning);
    }

    #[test]
    fn tamper_sources() {
        let hunt = json!({"Schema": [], "Results": [{"Total": 100, "Compliant": 96}]});
        assert_eq!(parse_hunt(&hunt).unwrap(), (96, 100));
        assert!(parse_hunt(&json!({"Results": []})).is_err());
        let rows = vec![
            json!({"configurationId": "scid-2010", "isCompliant": true}),
            json!({"configurationId": "scid-2010", "isCompliant": false}),
            json!({"configurationId": "scid-2001", "isCompliant": false}),
        ];
        assert_eq!(parse_assessment_rows(&rows), (1, 2));
        assert_eq!(tamper_001(96, 100).unwrap().0, FindingStatus::Pass);
        assert_eq!(tamper_001(1, 2).unwrap().0, FindingStatus::Warning);
        assert!(tamper_001(0, 0).is_err());
    }
}
