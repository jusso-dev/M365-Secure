//! Defender for Office 365, Exchange Online Protection, Purview compliance and Defender for
//! Identity checks. Policy state is read from the policy cmdlets and Graph; Secure Score is
//! reported only as information.

pub mod compliance;
pub mod defender;
pub mod mdi;
pub mod securescore;

use anyhow::Result;
use async_trait::async_trait;

use super::exchange::exo::Exo;
use super::{record_one, AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::Finding;
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

pub struct SecurityModule;

#[async_trait]
impl AssessmentModule for SecurityModule {
    fn name(&self) -> &str {
        "Security"
    }

    fn description(&self) -> &str {
        "Defender for Office 365 and EOP policies, Purview labels/DLP/alerts, Defender for Identity sensors"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();
        let exo = Exo::new(graph, &tenant.tenant_id);

        record_one(
            &mut findings,
            securescore::check_secure_score(graph, registry).await,
            "DEFENDER-SECURESCORE-001",
            "Security",
            "Microsoft Defender",
            "Microsoft Secure Score",
        );

        defender::run_all(&exo, tenant, registry, &mut findings).await;

        compliance::check_labels(graph, registry, &mut findings).await;
        compliance::check_dlp(&exo, registry, &mut findings).await;
        compliance::check_alert_policies(&exo, registry, &mut findings).await;
        compliance::check_communication_compliance(&exo, registry, &mut findings).await;

        record_one(
            &mut findings,
            mdi::check_sensors(graph, tenant, registry).await,
            "MDI-SENSOR-001",
            "Security",
            "Defender for Identity",
            "Sensor Health",
        );

        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: serde_json::json!({ "module": "security" }),
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}
