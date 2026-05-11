use anyhow::Result;
use std::path::Path;

use crate::assessment::engine::AssessmentSummary;
use crate::assessment::finding::Finding;
use crate::compliance::mapping::ComplianceResult;

#[derive(serde::Serialize)]
struct JsonReport<'a> {
    summary: &'a AssessmentSummary,
    findings: &'a [Finding],
    compliance: &'a [ComplianceResult],
}

pub fn generate_json_report(
    path: &Path,
    summary: &AssessmentSummary,
    findings: &[Finding],
    compliance_results: &[ComplianceResult],
) -> Result<()> {
    let report = JsonReport {
        summary,
        findings,
        compliance: compliance_results,
    };

    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(path, json)?;
    tracing::info!("JSON report written to {}", path.display());
    Ok(())
}
