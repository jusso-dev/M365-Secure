//! SharePoint, OneDrive, Teams and Forms. The SharePoint checks read the CSOM tenant object through the
//! SharePoint admin API, the Teams checks read the Teams admin backend; both fall back to `Unknown` with
//! the consent hint when the signed-in app is not permitted for the resource.

mod forms;
mod sharepoint;
mod teams;

use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::Finding;
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct CollaborationModule;

#[async_trait]
impl AssessmentModule for CollaborationModule {
    fn name(&self) -> &str {
        "Collaboration"
    }

    fn description(&self) -> &str {
        "SharePoint, OneDrive, Teams, and Forms collaboration assessment module"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();
        let mut raw_data = serde_json::json!({});

        let spo = sharepoint::collect(graph).await;
        findings.extend(sharepoint::evaluate(&spo, tenant, registry));
        raw_data["sharepoint"] = spo.raw;

        let teams = teams::collect(graph).await;
        findings.extend(teams::evaluate(&teams, registry));
        raw_data["teams"] = teams.raw;

        forms::run(graph, registry, &mut findings, &mut raw_data).await;

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data,
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}
