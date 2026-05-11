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
