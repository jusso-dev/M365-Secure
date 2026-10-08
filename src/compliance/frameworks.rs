use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scoring_method: String,
    #[serde(default)]
    pub controls: Vec<FrameworkControl>,
    /// Top-level section names keyed by their number prefix (e.g. "5" -> "Microsoft Entra admin center").
    #[serde(default)]
    pub sections: HashMap<String, String>,
}

impl ComplianceFramework {
    /// Section name for a control id, by its leading number (`5.2.2.2` -> section "5").
    pub fn section_for(&self, control_id: &str) -> String {
        let prefix = control_id.split(['.', '-']).next().unwrap_or("");
        self.sections.get(prefix).cloned().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkControl {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub section: String,
    #[serde(default)]
    pub check_ids: Vec<String>,
}

pub struct FrameworkLibrary {
    frameworks: HashMap<String, ComplianceFramework>,
}

impl FrameworkLibrary {
    pub fn load(frameworks_dir: &Path) -> Result<Self> {
        let mut frameworks = HashMap::new();

        let framework_files = vec![
            ("cis-m365-v6", "CIS Microsoft 365 Foundations Benchmark v6"),
            ("cis-m365-v7", "CIS Microsoft 365 Foundations Benchmark v7"),
            ("nist-800-53-r5", "NIST 800-53 Rev 5"),
            ("nist-csf", "NIST CSF 2.0"),
            ("iso-27001", "ISO 27001:2022"),
            ("soc2-tsc", "SOC 2 TSC"),
            ("pci-dss-v4", "PCI DSS v4.0.1"),
            ("hipaa", "HIPAA Security Rule"),
            ("cmmc", "CMMC 2.0"),
            ("cisa-scuba", "CISA SCuBA"),
            ("fedramp", "FedRAMP"),
            ("essential-eight", "Essential Eight"),
            ("mitre-attack", "MITRE ATT&CK"),
            ("cis-controls-v8", "CIS Controls v8"),
            ("entra-id-stig", "Entra ID STIG"),
            ("stig", "DISA STIG"),
        ];

        for (file_id, display_name) in &framework_files {
            let path = frameworks_dir.join(format!("{}.json", file_id));
            if path.exists() {
                match std::fs::read_to_string(&path) {
                    Ok(data) => match serde_json::from_str::<serde_json::Value>(&data) {
                        Ok(json) => {
                            let framework = ComplianceFramework {
                                id: file_id.to_string(),
                                name: display_name.to_string(),
                                version: json
                                    .get("version")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("1.0")
                                    .to_string(),
                                description: json
                                    .get("description")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                scoring_method: json
                                    .get("scoringMethod")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("coverage-mapping")
                                    .to_string(),
                                controls: extract_controls(&json),
                                sections: json
                                    .get("sections")
                                    .and_then(|s| s.as_object())
                                    .map(|o| {
                                        o.iter()
                                            .filter_map(|(k, v)| {
                                                v.as_str().map(|n| (k.clone(), n.to_string()))
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                            };
                            frameworks.insert(file_id.to_string(), framework);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse framework {}: {}", file_id, e);
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to read framework file {}: {}", file_id, e);
                    }
                }
            }
        }

        tracing::info!("Loaded {} compliance frameworks", frameworks.len());
        Ok(Self { frameworks })
    }

    pub fn all(&self) -> impl Iterator<Item = &ComplianceFramework> {
        self.frameworks.values()
    }
}

fn extract_controls(json: &serde_json::Value) -> Vec<FrameworkControl> {
    let mut controls = Vec::new();

    // Try "controls" array first
    if let Some(ctrl_array) = json.get("controls").and_then(|c| c.as_array()) {
        for ctrl in ctrl_array {
            controls.push(FrameworkControl {
                id: ctrl
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: ctrl
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                description: ctrl
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                section: ctrl
                    .get("section")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                check_ids: ctrl
                    .get("checkIds")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
    }

    // Try "sections" with nested controls
    if let Some(sections) = json.get("sections").and_then(|s| s.as_array()) {
        for section in sections {
            let section_name = section.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(sec_controls) = section.get("controls").and_then(|c| c.as_array()) {
                for ctrl in sec_controls {
                    controls.push(FrameworkControl {
                        id: ctrl
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        name: ctrl
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        description: ctrl
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        section: section_name.to_string(),
                        check_ids: ctrl
                            .get("checkIds")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    });
                }
            }
        }
    }

    controls
}
