use anyhow::Result;
use std::path::Path;

use crate::assessment::engine::AssessmentSummary;
use crate::assessment::finding::Finding;
use crate::compliance::mapping::ComplianceResult;

#[derive(serde::Serialize)]
struct JsonReport<'a> {
    /// Bumped when the shape of this file changes. 1.1 added populated framework mappings and `tool`.
    schema_version: &'static str,
    tool: ToolInfo,
    summary: &'a AssessmentSummary,
    findings: &'a [Finding],
    compliance: &'a [ComplianceResult],
}

#[derive(serde::Serialize)]
struct ToolInfo {
    name: &'static str,
    version: &'static str,
}

pub fn generate_json_report(
    path: &Path,
    summary: &AssessmentSummary,
    findings: &[Finding],
    compliance_results: &[ComplianceResult],
) -> Result<()> {
    let report = JsonReport {
        schema_version: "1.1",
        tool: ToolInfo {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        summary,
        findings,
        compliance: compliance_results,
    };

    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(path, json)?;
    tracing::info!("JSON report written to {}", path.display());
    Ok(())
}
