use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use super::severity::Severity;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryFile {
    #[allow(dead_code)]
    schema_version: String,
    checks: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SeverityFile {
    checks: HashMap<String, String>,
}

pub struct ControlRegistry {
    control_count: usize,
    severity_overrides: HashMap<String, Severity>,
}

impl ControlRegistry {
    pub fn load(controls_dir: &Path) -> Result<Self> {
        let registry_path = controls_dir.join("registry.json");
        let severity_path = controls_dir.join("risk-severity.json");

        // Load severity overrides
        let severity_overrides = if severity_path.exists() {
            let data = std::fs::read_to_string(&severity_path)?;
            let sev_file: SeverityFile = serde_json::from_str(&data)?;
            sev_file
                .checks
                .into_iter()
                .filter_map(|(id, sev_str)| sev_str.parse::<Severity>().ok().map(|s| (id, s)))
                .collect()
        } else {
            HashMap::new()
        };

        // Load registry
        let mut control_count = 0;
        if registry_path.exists() {
            let data = std::fs::read_to_string(&registry_path)?;
            let registry: RegistryFile = serde_json::from_str(&data)?;
            control_count = registry.checks.len();
        }

        tracing::info!("Loaded {} controls from registry", control_count);

        Ok(Self {
            control_count,
            severity_overrides,
        })
    }

    pub fn get_severity(&self, check_id: &str) -> Severity {
        self.severity_overrides
            .get(check_id)
            .copied()
            .unwrap_or(Severity::Medium)
    }

    pub fn control_count(&self) -> usize {
        self.control_count
    }
}
