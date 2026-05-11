use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::frameworks::{ComplianceFramework, FrameworkLibrary};
use crate::assessment::finding::{Finding, FindingStatus};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComplianceResult {
    pub framework_id: String,
    pub framework_name: String,
    pub total_controls: usize,
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

impl ComplianceMapper {
    pub fn map_findings(findings: &[Finding], library: &FrameworkLibrary) -> Vec<ComplianceResult> {
        let finding_map: HashMap<&str, &Finding> =
            findings.iter().map(|f| (f.check_id.as_str(), f)).collect();

        library
            .all()
            .map(|framework| Self::map_framework(framework, &finding_map))
            .collect()
    }

    fn map_framework(
        framework: &ComplianceFramework,
        findings: &HashMap<&str, &Finding>,
    ) -> ComplianceResult {
        let mut control_results = Vec::new();
        let mut assessed = 0;
        let mut passing = 0;
        let mut failing = 0;

        for control in &framework.controls {
            if control.check_ids.is_empty() {
                continue;
            }

            let check_statuses: Vec<CheckStatus> = control
                .check_ids
                .iter()
                .filter_map(|check_id| {
                    findings.get(check_id.as_str()).map(|f| CheckStatus {
                        check_id: check_id.clone(),
                        status: f.status,
                        setting: f.setting.clone(),
                    })
                })
                .collect();

            if check_statuses.is_empty() {
                continue;
            }

            assessed += 1;

            // Control passes only if ALL mapped checks pass
            let all_pass = check_statuses
                .iter()
                .all(|cs| cs.status == FindingStatus::Pass);
            let any_fail = check_statuses
                .iter()
                .any(|cs| cs.status == FindingStatus::Fail);

            let status = if all_pass {
                passing += 1;
                FindingStatus::Pass
            } else if any_fail {
                failing += 1;
                FindingStatus::Fail
            } else {
                FindingStatus::Warning
            };

            control_results.push(ControlResult {
                control_id: control.id.clone(),
                control_name: control.name.clone(),
                section: control.section.clone(),
                status,
                mapped_checks: control.check_ids.clone(),
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
            total_controls: framework.controls.len(),
            assessed_controls: assessed,
            passing_controls: passing,
            failing_controls: failing,
            pass_rate,
            control_results,
        }
    }
}
