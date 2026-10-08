use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::frameworks::{ComplianceFramework, FrameworkLibrary};
use crate::assessment::finding::{Finding, FindingStatus, FrameworkMappings};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComplianceResult {
    pub framework_id: String,
    pub framework_name: String,
    /// Distinct framework controls that at least one check in this scan maps to.
    pub total_controls: usize,
    /// Controls with at least one check that produced a Pass, Fail, Warning or Review.
    pub assessed_controls: usize,
    pub passing_controls: usize,
    pub failing_controls: usize,
    pub pass_rate: f64,
    pub control_results: Vec<ControlResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub control_id: String,
    pub control_name: String,
    pub section: String,
    pub status: FindingStatus,
    pub mapped_checks: Vec<String>,
    pub check_statuses: Vec<CheckStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckStatus {
    pub check_id: String,
    pub status: FindingStatus,
    pub setting: String,
}

pub struct ComplianceMapper;

/// The framework references on a finding for a given framework file id.
fn refs_for<'a>(m: &'a FrameworkMappings, framework_id: &str) -> Option<&'a [String]> {
    let v: &Vec<String> = match framework_id {
        "cis-m365-v6" => &m.cis,
        "cis-m365-v7" => &m.cis_v7,
        "nist-800-53-r5" | "nist-800-53" => &m.nist,
        "nist-csf" => &m.nist_csf,
        "iso-27001" => &m.iso27001,
        "soc2-tsc" | "soc2" => &m.soc2,
        "pci-dss-v4" | "pci-dss" => &m.pci_dss,
        "hipaa" => &m.hipaa,
        "cmmc" => &m.cmmc,
        "cisa-scuba" => &m.cisa_scuba,
        "fedramp" => &m.fedramp,
        "essential-eight" => &m.essential_eight,
        "mitre-attack" => &m.mitre_attack,
        other => m.other.get(other)?,
    };
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Aggregate check statuses into a control status.
/// Pass needs every scored check to pass; any Fail fails the control; Warning/Review make it partial.
/// Controls whose checks were all Unknown, Info or Not Licensed are not assessed.
fn aggregate(statuses: &[FindingStatus]) -> Option<FindingStatus> {
    let scored: Vec<FindingStatus> = statuses
        .iter()
        .copied()
        .filter(|s| {
            matches!(
                s,
                FindingStatus::Pass
                    | FindingStatus::Fail
                    | FindingStatus::Warning
                    | FindingStatus::Review
            )
        })
        .collect();
    if scored.is_empty() {
        return None;
    }
    Some(if scored.iter().all(|s| *s == FindingStatus::Pass) {
        FindingStatus::Pass
    } else if scored.contains(&FindingStatus::Fail) {
        FindingStatus::Fail
    } else {
        FindingStatus::Warning
    })
}

impl ComplianceMapper {
    /// Build per-framework coverage from the framework references attached to each finding.
    /// Framework files supply the label, version and section names; the registry supplies the mapping.
    pub fn map_findings(findings: &[Finding], library: &FrameworkLibrary) -> Vec<ComplianceResult> {
        let mut results: Vec<ComplianceResult> = library
            .all()
            .map(|framework| Self::map_framework(framework, findings))
            .filter(|r| r.total_controls > 0)
            .collect();
        results.sort_by(|a, b| a.framework_id.cmp(&b.framework_id));
        results
    }

    fn map_framework(framework: &ComplianceFramework, findings: &[Finding]) -> ComplianceResult {
        let mut by_control: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
        for f in findings {
            if let Some(refs) = refs_for(&f.framework_mappings, &framework.id) {
                for r in refs {
                    by_control.entry(r.clone()).or_default().push(f);
                }
            }
        }

        let mut control_results = Vec::new();
        let (mut assessed, mut passing, mut failing) = (0, 0, 0);
        for (control_id, checks) in &by_control {
            let check_statuses: Vec<CheckStatus> = checks
                .iter()
                .map(|f| CheckStatus {
                    check_id: f.check_id.clone(),
                    status: f.status,
                    setting: f.setting.clone(),
                })
                .collect();
            let Some(status) = aggregate(&checks.iter().map(|f| f.status).collect::<Vec<_>>())
            else {
                continue;
            };
            assessed += 1;
            match status {
                FindingStatus::Pass => passing += 1,
                FindingStatus::Fail => failing += 1,
                _ => {}
            }
            control_results.push(ControlResult {
                control_id: control_id.clone(),
                control_name: String::new(),
                section: framework.section_for(control_id),
                status,
                mapped_checks: checks.iter().map(|f| f.check_id.clone()).collect(),
                check_statuses,
            });
        }

        let pass_rate = if assessed > 0 {
            (passing as f64 / assessed as f64) * 100.0
        } else {
            0.0
        };

        ComplianceResult {
            framework_id: framework.id.clone(),
            framework_name: framework.name.clone(),
            total_controls: by_control.len(),
            assessed_controls: assessed,
            passing_controls: passing,
            failing_controls: failing,
            pass_rate,
            control_results,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_status_aggregates_scored_checks_only() {
        use FindingStatus::*;
        assert_eq!(aggregate(&[Pass, Pass]), Some(Pass));
        assert_eq!(aggregate(&[Pass, Fail]), Some(Fail));
        assert_eq!(aggregate(&[Pass, Warning]), Some(Warning));
        assert_eq!(aggregate(&[Pass, Unknown]), Some(Pass));
        assert_eq!(aggregate(&[Unknown, NotLicensed, Info]), None);
    }

    #[test]
    fn refs_follow_framework_file_ids() {
        let mut m = FrameworkMappings::default();
        m.add("cis-m365-v7", "5.2.2.2;5.1.2.1");
        m.add("nis2", "21.1");
        assert_eq!(refs_for(&m, "cis-m365-v7").unwrap().len(), 2);
        assert!(refs_for(&m, "cis-m365-v6").is_none());
        assert_eq!(refs_for(&m, "nis2").unwrap(), ["21.1"]);
    }
}
