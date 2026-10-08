pub mod azure;
pub mod collaboration;
pub mod exchange;
pub mod hybrid;
pub mod identity;
pub mod intune;
pub mod inventory;
pub mod licensing;
pub mod powerbi;
pub mod purview;
pub mod security;
pub mod soc2;
pub mod value_opportunity;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::Finding;
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub module_name: String,
    pub findings: Vec<Finding>,
    pub raw_data: serde_json::Value,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub modules: Vec<String>,
    pub quick_scan: bool,
    pub include_inventory: bool,
    pub include_soc2: bool,
    pub include_powerbi: bool,
    pub include_value: bool,
    pub output_formats: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            modules: vec![],
            quick_scan: false,
            include_inventory: false,
            include_soc2: false,
            include_powerbi: false,
            include_value: false,
            output_formats: vec!["html".to_string(), "csv".to_string(), "json".to_string()],
        }
    }
}

#[async_trait]
pub trait AssessmentModule: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult>;
}

/// Record a check's outcome. On error the check still appears, as `Unknown` with the reason, so a
/// permission problem or an unsupported API is visible in the report instead of silently dropping the check.
pub fn record(
    findings: &mut Vec<Finding>,
    result: Result<Vec<Finding>>,
    check_id: &str,
    category: &str,
    section: &str,
    setting: &str,
) {
    match result {
        Ok(f) => findings.extend(f),
        Err(e) => {
            tracing::warn!("{check_id} could not run: {e}");
            findings.push(Finding::unknown(
                check_id,
                category,
                section,
                setting,
                "The check did not complete.",
                e,
            ));
        }
    }
}

/// Single-finding variant of [`record`].
pub fn record_one(
    findings: &mut Vec<Finding>,
    result: Result<Finding>,
    check_id: &str,
    category: &str,
    section: &str,
    setting: &str,
) {
    record(
        findings,
        result.map(|f| vec![f]),
        check_id,
        category,
        section,
        setting,
    );
}
