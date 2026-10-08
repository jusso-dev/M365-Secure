use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use super::severity::Severity;
use crate::assessment::finding::FrameworkMappings;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryFile {
    #[allow(dead_code)]
    #[serde(default)]
    schema_version: String,
    checks: Vec<RegistryCheck>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryCheck {
    check_id: String,
    name: String,
    category: String,
    #[serde(default)]
    collector: String,
    #[serde(default)]
    has_automated_check: bool,
    #[serde(default)]
    licensing: Option<LicensingInfo>,
    #[serde(default)]
    impact_rating: Option<ImpactRating>,
    /// `{ "<framework key>": { "controlId": "A;B;C", ... } }`
    #[serde(default)]
    frameworks: HashMap<String, FrameworkRef>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpactRating {
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrameworkRef {
    #[serde(default)]
    control_id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LicensingInfo {
    pub minimum: Option<String>,
    #[serde(default, rename = "requiredServicePlans")]
    pub required_service_plans: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SeverityFile {
    checks: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlDefinition {
    pub check_id: String,
    pub name: String,
    pub category: String,
    pub collector: String,
    pub has_automated_check: bool,
    pub severity: Severity,
    pub licensing: Option<LicensingInfo>,
    pub framework_mappings: FrameworkMappings,
}

/// The control registry: `controls/registry.json` plus any overlay files in `controls/registry.d/*.json`.
/// Overlays use the same `{ "checks": [...] }` shape and are applied in file-name order; a check in an
/// overlay replaces the base entry with the same id. Modules add their new checks as overlays so the
/// base file stays reviewable.
pub struct ControlRegistry {
    controls: HashMap<String, ControlDefinition>,
    severity_overrides: HashMap<String, Severity>,
}

impl ControlRegistry {
    pub fn load(controls_dir: &Path) -> Result<Self> {
        let registry_path = controls_dir.join("registry.json");
        let severity_path = controls_dir.join("risk-severity.json");

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

        let mut files = Vec::new();
        if registry_path.exists() {
            files.push(registry_path);
        }
        let overlay_dir = controls_dir.join("registry.d");
        if overlay_dir.is_dir() {
            let mut overlays: Vec<_> = std::fs::read_dir(&overlay_dir)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect();
            overlays.sort();
            files.extend(overlays);
        }

        let mut controls = HashMap::new();
        for path in files {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let registry: RegistryFile = serde_json::from_str(&data)
                .with_context(|| format!("parsing {}", path.display()))?;
            for check in registry.checks {
                let definition = Self::definition(check, &severity_overrides);
                controls.insert(definition.check_id.clone(), definition);
            }
        }

        tracing::info!("Loaded {} controls from registry", controls.len());
        Ok(Self {
            controls,
            severity_overrides,
        })
    }

    fn definition(
        check: RegistryCheck,
        overrides: &HashMap<String, Severity>,
    ) -> ControlDefinition {
        let registry_severity = check
            .impact_rating
            .as_ref()
            .and_then(|r| r.severity.as_deref())
            .and_then(|s| s.parse::<Severity>().ok());
        let severity = overrides
            .get(&check.check_id)
            .copied()
            .or(registry_severity)
            .unwrap_or(Severity::Medium);

        let mut framework_mappings = FrameworkMappings::default();
        let mut keys: Vec<_> = check.frameworks.keys().cloned().collect();
        keys.sort();
        for key in keys {
            framework_mappings.add(&key, &check.frameworks[&key].control_id);
        }

        ControlDefinition {
            check_id: check.check_id,
            name: check.name,
            category: check.category,
            collector: check.collector,
            has_automated_check: check.has_automated_check,
            severity,
            licensing: check.licensing,
            framework_mappings,
        }
    }

    /// Severity for a check: `risk-severity.json` override, then the registry's impact rating, then Medium.
    pub fn get_severity(&self, check_id: &str) -> Severity {
        self.severity_overrides
            .get(check_id)
            .copied()
            .or_else(|| self.controls.get(check_id).map(|c| c.severity))
            .unwrap_or(Severity::Medium)
    }

    /// Framework references for a check, empty when the registry has none.
    pub fn mappings(&self, check_id: &str) -> FrameworkMappings {
        self.controls
            .get(check_id)
            .map(|c| c.framework_mappings.clone())
            .unwrap_or_default()
    }

    pub fn control_count(&self) -> usize {
        self.controls.len()
    }
}
