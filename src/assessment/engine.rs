use anyhow::Result;
use chrono::Utc;
use colored::Colorize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::finding::{Finding, FindingStatus};
use super::registry::ControlRegistry;
use crate::graph::GraphClient;
use crate::modules::{self, AssessmentModule, ModuleResult, ScanConfig};

pub struct AssessmentEngine {
    graph: GraphClient,
    registry: ControlRegistry,
    findings: Arc<RwLock<Vec<Finding>>>,
    module_results: Arc<RwLock<HashMap<String, ModuleResult>>>,
    tenant_info: Arc<RwLock<Option<TenantInfo>>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TenantInfo {
    pub tenant_id: String,
    pub display_name: String,
    pub verified_domains: Vec<String>,
    pub primary_domain: String,
    pub license_skus: Vec<LicenseSku>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LicenseSku {
    pub sku_id: String,
    pub sku_part_number: String,
    pub consumed_units: u32,
    pub prepaid_units: u32,
    pub service_plans: Vec<String>,
}

impl TenantInfo {
    pub fn has_service_plan(&self, plan: &str) -> bool {
        self.license_skus.iter().any(|sku| {
            sku.service_plans
                .iter()
                .any(|sp| sp.eq_ignore_ascii_case(plan))
        })
    }

    pub fn has_e5(&self) -> bool {
        self.license_skus
            .iter()
            .any(|sku| sku.sku_part_number.contains("E5") || sku.sku_part_number.contains("SPE_E5"))
    }

    pub fn has_p2(&self) -> bool {
        self.has_service_plan("AAD_PREMIUM_P2")
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssessmentSummary {
    pub tenant: TenantInfo,
    pub timestamp: String,
    pub duration_seconds: f64,
    pub total_checks: usize,
    pub status_counts: HashMap<String, usize>,
    pub severity_counts: HashMap<String, usize>,
    pub score: f64,
    pub modules_run: Vec<String>,
    pub modules_failed: Vec<String>,
}

impl AssessmentEngine {
    pub fn new(graph: GraphClient, registry: ControlRegistry) -> Self {
        Self {
            graph,
            registry,
            findings: Arc::new(RwLock::new(Vec::new())),
            module_results: Arc::new(RwLock::new(HashMap::new())),
            tenant_info: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn run_full_assessment(&self, config: &ScanConfig) -> Result<AssessmentSummary> {
        let start = std::time::Instant::now();

        // Step 1: Collect tenant info
        println!(
            "\n{}",
            "=== M365 Security Assessment ===".bright_cyan().bold()
        );
        println!("{}", "Collecting tenant information...".dimmed());

        let tenant_info = self.collect_tenant_info().await?;
        println!(
            "  Tenant: {} ({})",
            tenant_info.display_name.bright_white(),
            tenant_info.primary_domain.bright_blue()
        );
        println!("  Licenses: {} SKUs", tenant_info.license_skus.len());

        {
            let mut ti = self.tenant_info.write().await;
            *ti = Some(tenant_info.clone());
        }

        // Step 2: Build module list
        let modules = self.build_module_list(config);
        println!("\n  Running {} assessment modules...\n", modules.len());

        // Step 3: Run modules
        for module in &modules {
            let section = module.name();
            println!(
                "  {} {} - {}",
                ">>".bright_cyan(),
                section.bright_white().bold(),
                module.description().dimmed()
            );

            match module.run(&self.graph, &tenant_info, &self.registry).await {
                Ok(result) => {
                    let pass_count = result
                        .findings
                        .iter()
                        .filter(|f| f.status == FindingStatus::Pass)
                        .count();
                    let fail_count = result
                        .findings
                        .iter()
                        .filter(|f| f.status == FindingStatus::Fail)
                        .count();
                    let warn_count = result
                        .findings
                        .iter()
                        .filter(|f| f.status == FindingStatus::Warning)
                        .count();

                    println!(
                        "     {} checks: {} pass, {} fail, {} warn",
                        result.findings.len().to_string().bright_white(),
                        pass_count.to_string().bright_green(),
                        fail_count.to_string().bright_red(),
                        warn_count.to_string().bright_yellow(),
                    );

                    let mut findings = self.findings.write().await;
                    findings.extend(result.findings.clone());
                    let mut results = self.module_results.write().await;
                    results.insert(section.to_string(), result);
                }
                Err(e) => {
                    println!("     {} {}", "ERROR:".bright_red(), e);
                    let mut results = self.module_results.write().await;
                    results.insert(
                        section.to_string(),
                        ModuleResult {
                            module_name: section.to_string(),
                            findings: vec![],
                            raw_data: serde_json::Value::Null,
                            error: Some(e.to_string()),
                            duration_ms: 0,
                        },
                    );
                }
            }
        }

        // Step 4: Calculate summary
        let findings = self.findings.read().await;
        let results = self.module_results.read().await;

        let mut status_counts: HashMap<String, usize> = HashMap::new();
        let mut severity_counts: HashMap<String, usize> = HashMap::new();

        for f in findings.iter() {
            *status_counts.entry(f.status.to_string()).or_insert(0) += 1;
            *severity_counts.entry(f.severity.to_string()).or_insert(0) += 1;
        }

        let total_scoreable = findings
            .iter()
            .filter(|f| matches!(f.status, FindingStatus::Pass | FindingStatus::Fail))
            .count();
        let pass_count = *status_counts.get("Pass").unwrap_or(&0);
        let score = if total_scoreable > 0 {
            (pass_count as f64 / total_scoreable as f64) * 100.0
        } else {
            0.0
        };

        let modules_failed: Vec<String> = results
            .iter()
            .filter(|(_, r)| r.error.is_some())
            .map(|(name, _)| name.clone())
            .collect();

        let summary = AssessmentSummary {
            tenant: tenant_info,
            timestamp: Utc::now().to_rfc3339(),
            duration_seconds: start.elapsed().as_secs_f64(),
            total_checks: findings.len(),
            status_counts,
            severity_counts,
            score,
            modules_run: results.keys().cloned().collect(),
            modules_failed,
        };

        // Print summary
        println!("\n{}", "=== Assessment Complete ===".bright_cyan().bold());
        println!(
            "  Total Checks: {}",
            summary.total_checks.to_string().bright_white()
        );
        println!("  Score: {:.1}%", summary.score);
        println!("  Duration: {:.1}s", summary.duration_seconds);
        println!();

        Ok(summary)
    }

    pub async fn run_module_assessment(
        &self,
        module_name: &str,
        config: &ScanConfig,
    ) -> Result<AssessmentSummary> {
        let mut filtered_config = config.clone();
        filtered_config.modules = vec![module_name.to_string()];
        self.run_full_assessment(&filtered_config).await
    }

    pub async fn get_findings(&self) -> Vec<Finding> {
        self.findings.read().await.clone()
    }

    async fn collect_tenant_info(&self) -> Result<TenantInfo> {
        let org: serde_json::Value = self.graph.get_json("/v1.0/organization").await?;
        let org_value = org["value"]
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| anyhow::anyhow!("No organization data returned"))?;

        let tenant_id = org_value["id"].as_str().unwrap_or_default().to_string();
        let display_name = org_value["displayName"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let domains: Vec<serde_json::Value> = self.graph.get_all("/v1.0/domains").await?;
        let verified_domains: Vec<String> = domains
            .iter()
            .filter(|d| d["isVerified"].as_bool().unwrap_or(false))
            .filter_map(|d| d["id"].as_str().map(String::from))
            .collect();
        let primary_domain = domains
            .iter()
            .find(|d| d["isDefault"].as_bool().unwrap_or(false))
            .and_then(|d| d["id"].as_str())
            .unwrap_or_default()
            .to_string();

        let skus: Vec<serde_json::Value> = self.graph.get_all("/v1.0/subscribedSkus").await?;
        let license_skus: Vec<LicenseSku> = skus
            .iter()
            .map(|sku| {
                let service_plans: Vec<String> = sku["servicePlans"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|sp| sp["servicePlanName"].as_str().map(String::from))
                    .collect();

                LicenseSku {
                    sku_id: sku["skuId"].as_str().unwrap_or_default().to_string(),
                    sku_part_number: sku["skuPartNumber"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    consumed_units: sku["consumedUnits"].as_u64().unwrap_or(0) as u32,
                    prepaid_units: sku["prepaidUnits"]["enabled"].as_u64().unwrap_or(0) as u32,
                    service_plans,
                }
            })
            .collect();

        Ok(TenantInfo {
            tenant_id,
            display_name,
            verified_domains,
            primary_domain,
            license_skus,
        })
    }

    fn build_module_list(&self, config: &ScanConfig) -> Vec<Box<dyn AssessmentModule>> {
        let mut module_list: Vec<Box<dyn AssessmentModule>> = Vec::new();

        let default_modules = [
            "identity",
            "licensing",
            "exchange",
            "security",
            "collaboration",
            "intune",
            "hybrid",
        ];

        let modules_to_run = if config.modules.is_empty() {
            default_modules.iter().map(|s| s.to_string()).collect()
        } else {
            config.modules.clone()
        };

        for module_name in &modules_to_run {
            match module_name.to_lowercase().as_str() {
                "identity" | "entra" => {
                    module_list.push(Box::new(modules::identity::IdentityModule))
                }
                "licensing" => module_list.push(Box::new(modules::licensing::LicensingModule)),
                "exchange" | "email" => {
                    module_list.push(Box::new(modules::exchange::ExchangeModule))
                }
                "security" | "defender" => {
                    module_list.push(Box::new(modules::security::SecurityModule))
                }
                "collaboration" | "sharepoint" | "teams" => {
                    module_list.push(Box::new(modules::collaboration::CollaborationModule))
                }
                "intune" | "devices" => module_list.push(Box::new(modules::intune::IntuneModule)),
                "hybrid" => module_list.push(Box::new(modules::hybrid::HybridModule)),
                "powerbi" => module_list.push(Box::new(modules::powerbi::PowerBIModule)),
                "purview" => module_list.push(Box::new(modules::purview::PurviewModule)),
                "inventory" => module_list.push(Box::new(modules::inventory::InventoryModule)),
                "soc2" => module_list.push(Box::new(modules::soc2::SOC2Module)),
                "value" | "valueopportunity" => {
                    module_list.push(Box::new(modules::value_opportunity::ValueOpportunityModule))
                }
                _ => {
                    tracing::warn!("Unknown module: {}", module_name);
                }
            }
        }

        if config.quick_scan {
            tracing::info!("QuickScan mode: only running Critical and High severity checks");
        }

        module_list
    }
}
