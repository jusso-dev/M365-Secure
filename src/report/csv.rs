use anyhow::Result;
use std::path::Path;

use crate::assessment::finding::Finding;

pub fn generate_csv_report(path: &Path, findings: &[Finding]) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record([
        "Check ID",
        "Category",
        "Section",
        "Setting",
        "Description",
        "Status",
        "Severity",
        "Current Value",
        "Expected Value",
        "Remediation",
        "CIS M365 v7",
        "CIS M365 v6",
        "NIST CSF 2.0",
        "Essential Eight",
        "Timestamp",
    ])?;

    for f in findings {
        wtr.write_record([
            &f.check_id,
            &f.category,
            &f.section,
            &f.setting,
            &f.description,
            &f.status.to_string(),
            &f.severity.to_string(),
            &f.current_value,
            &f.expected_value,
            &f.remediation,
            &f.framework_mappings.cis_v7.join("; "),
            &f.framework_mappings.cis.join("; "),
            &f.framework_mappings.nist_csf.join("; "),
            &f.framework_mappings.essential_eight.join("; "),
            &f.timestamp.to_rfc3339(),
        ])?;
    }

    wtr.flush()?;
    tracing::info!("CSV report written to {}", path.display());
    Ok(())
}

/// One CSV per finding category (Entra, Exchange, SharePoint, ...), so a reviewer can hand each area
/// to its owner. Section-level detail stays in the combined findings file.
pub fn generate_section_csvs(
    output_dir: &Path,
    findings: &[Finding],
    tenant_domain: &str,
) -> Result<Vec<String>> {
    let mut by_category: std::collections::BTreeMap<String, Vec<&Finding>> =
        std::collections::BTreeMap::new();
    for f in findings {
        let key = if f.category.trim().is_empty() {
            f.section.clone()
        } else {
            f.category.clone()
        };
        by_category.entry(key).or_default().push(f);
    }

    let mut generated = Vec::new();
    for (category, category_findings) in &by_category {
        let slug: String = category
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .trim_matches('-')
            .to_string();
        let path = output_dir.join(format!("{}-{}.csv", slug, tenant_domain));
        let owned: Vec<Finding> = category_findings.iter().map(|f| (*f).clone()).collect();
        generate_csv_report(&path, &owned)?;
        generated.push(path.display().to_string());
    }
    Ok(generated)
}
