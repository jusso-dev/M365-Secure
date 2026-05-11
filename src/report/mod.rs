pub mod csv;
pub mod html;
pub mod json;

use anyhow::Result;
use std::path::Path;

use crate::assessment::engine::AssessmentSummary;
use crate::assessment::finding::Finding;
use crate::compliance::mapping::ComplianceResult;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate(
        output_dir: &Path,
        summary: &AssessmentSummary,
        findings: &[Finding],
        compliance_results: &[ComplianceResult],
        formats: &[String],
    ) -> Result<Vec<String>> {
        std::fs::create_dir_all(output_dir)?;
        let mut generated = Vec::new();

        for format in formats {
            match format.as_str() {
                "html" => {
                    let path = output_dir.join(format!(
                        "_Assessment-Report_{}.html",
                        summary.tenant.primary_domain
                    ));
                    html::generate_html_report(&path, summary, findings, compliance_results)?;
                    generated.push(path.display().to_string());
                }
                "csv" => {
                    let path = output_dir.join(format!(
                        "_Assessment-Findings_{}.csv",
                        summary.tenant.primary_domain
                    ));
                    csv::generate_csv_report(&path, findings)?;
                    generated.push(path.display().to_string());

                    // Generate per-section CSVs
                    let section_files = csv::generate_section_csvs(
                        output_dir,
                        findings,
                        &summary.tenant.primary_domain,
                    )?;
                    generated.extend(section_files);
                }
                "json" => {
                    let path = output_dir.join(format!(
                        "_Assessment-Results_{}.json",
                        summary.tenant.primary_domain
                    ));
                    json::generate_json_report(&path, summary, findings, compliance_results)?;
                    generated.push(path.display().to_string());
                }
                _ => {
                    tracing::warn!("Unknown output format: {}", format);
                }
            }
        }

        Ok(generated)
    }
}
