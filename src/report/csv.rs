use anyhow::Result;
use std::collections::HashMap;
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

pub fn generate_section_csvs(
    output_dir: &Path,
    findings: &[Finding],
    tenant_domain: &str,
) -> Result<Vec<String>> {
    let mut by_section: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_section.entry(f.section.clone()).or_default().push(f);
    }

    let section_numbers = vec![
        ("Identity", "02"),
        ("Conditional Access", "05"),
        ("Enterprise Apps", "06"),
        ("App Registrations", "06b"),
        ("Password Policy", "07"),
        ("Entra Security", "07b"),
        ("Licensing", "08"),
        ("Exchange", "09"),
        ("Mail Flow", "10"),
        ("DNS", "12"),
        ("Intune", "13"),
        ("Compliance", "14"),
        ("Defender", "18"),
        ("SharePoint", "20"),
        ("Teams", "21"),
        ("Forms", "21c"),
        ("Power BI", "22"),
        ("Hybrid", "23"),
        ("Azure", "24"),
        ("Logging", "25"),
        ("Backup", "26"),
        ("Defender for Endpoint", "13b"),
        ("Authentication Methods", "03"),
        ("Privileged Access", "04"),
        ("Purview", "19c"),
        ("SOC 2", "33"),
        ("Inventory", "28"),
        ("Value Opportunity", "40"),
    ];

    let section_map: HashMap<&str, &str> = section_numbers.into_iter().collect();
    let mut generated = Vec::new();

    for (section, section_findings) in &by_section {
        let prefix = section_map.get(section.as_str()).unwrap_or(&"99");
        let filename = format!(
            "{}-{}-{}.csv",
            prefix,
            section.replace(' ', "-"),
            tenant_domain
        );
        let path = output_dir.join(&filename);

        let owned_findings: Vec<Finding> = section_findings.iter().map(|f| (*f).clone()).collect();
        generate_csv_report(&path, &owned_findings)?;
        generated.push(path.display().to_string());
    }

    Ok(generated)
}
