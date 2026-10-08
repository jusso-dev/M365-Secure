//! Azure management-plane checks (RBAC, Defender for Cloud, Key Vault, storage exposure, backup
//! immutability, Entra diagnostic settings and Sentinel), plus the Graph-side Microsoft 365 Backup and
//! Power Platform governance checks that evidence the same crownguard questions.
//!
//! Reads go through the Junction gateway (Resource Graph, Sentinel, Power Platform) so API versions,
//! paths and read-only policy come from Microsoft's published specifications. Providers Junction does not
//! carry (Authorization at root scope, aadiam, Insights diagnostic settings, Recovery Services vault
//! config) are read with direct ARM URLs through `GraphClient::get_resource_json`.
//!
//! Every ARM-backed check needs a token for Azure Resource Manager. When that token cannot be acquired
//! the module emits one `AZ-ACCESS-001` Unknown explaining the consent requirement instead of one
//! Unknown per check.

mod backup;
mod defender;
mod keyvault;
mod logging;
mod power_platform;
mod rbac;
mod workloads;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use super::{record_one, AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingBuilder, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::auth::{CloudEnvironment, Resource};
use crate::graph::GraphClient;
use crate::junction::JunctionGateway;

pub struct AzureModule;

/// A subscription the signed-in identity can read, from Resource Graph.
#[derive(Debug, Clone)]
pub(crate) struct Subscription {
    pub id: String,
    pub name: String,
    pub state: String,
}

/// Shared handles for the ARM-backed checks.
pub(crate) struct Ctx<'a> {
    pub graph: &'a GraphClient,
    pub jx: &'a JunctionGateway,
    pub registry: &'a ControlRegistry,
    pub subscriptions: Vec<Subscription>,
}

impl Ctx<'_> {
    /// ARM endpoint for the configured cloud (mirrors the Junction gateway's table).
    pub fn arm(&self) -> &'static str {
        arm_endpoint(self.graph.auth().cloud())
    }

    /// GET an ARM path (starting with `/`) that Junction does not catalogue.
    pub async fn arm_get(&self, path_and_query: &str) -> Result<Value> {
        let url = format!("{}{}", self.arm(), path_and_query);
        self.graph
            .get_resource_json(Resource::AzureResourceManager, &url)
            .await
    }

    /// GET an ARM collection, following `nextLink`.
    pub async fn arm_get_all(&self, path_and_query: &str) -> Result<Vec<Value>> {
        let url = format!("{}{}", self.arm(), path_and_query);
        self.graph
            .get_resource_all(Resource::AzureResourceManager, &url)
            .await
    }

    pub async fn resource_graph(&self, kql: &str) -> Result<Vec<Value>> {
        self.jx.resource_graph(kql).await
    }

    /// Display names for principal ids through Graph `directoryObjects/getByIds`, best effort.
    /// Returns `id -> "displayName (userPrincipalName)"`; ids that fail to resolve are absent.
    pub async fn resolve_principals(
        &self,
        ids: &[String],
    ) -> std::collections::BTreeMap<String, String> {
        let mut out = std::collections::BTreeMap::new();
        if ids.is_empty() || ids.len() > 50 {
            return out;
        }
        let url = format!(
            "{}/v1.0/directoryObjects/getByIds",
            self.graph.auth().cloud().graph_endpoint()
        );
        let body = json!({ "ids": ids, "types": ["user", "group", "servicePrincipal"] });
        match self
            .graph
            .post_resource_json(Resource::Graph, &url, &body)
            .await
        {
            Ok(v) => {
                for obj in v["value"].as_array().into_iter().flatten() {
                    let id = str_at(obj, "id");
                    if id.is_empty() {
                        continue;
                    }
                    let name = str_at(obj, "displayName");
                    let upn = str_at(obj, "userPrincipalName");
                    let label = if upn.is_empty() {
                        name.to_string()
                    } else {
                        format!("{name} ({upn})")
                    };
                    out.insert(id.to_string(), label);
                }
            }
            Err(e) => tracing::debug!("directoryObjects/getByIds failed: {e}"),
        }
        out
    }
}

pub(crate) fn arm_endpoint(cloud: CloudEnvironment) -> &'static str {
    match cloud {
        CloudEnvironment::Commercial => "https://management.azure.com",
        CloudEnvironment::GccHigh | CloudEnvironment::Dod => "https://management.usgovcloudapi.net",
    }
}

/// Start a finding with the registry's severity and framework references applied.
pub(crate) fn check(
    registry: &ControlRegistry,
    id: &str,
    category: &str,
    section: &str,
    setting: &str,
    description: &str,
) -> FindingBuilder {
    Finding::new(id, category, section, setting, description)
        .severity(registry.get_severity(id))
        .mappings(registry.mappings(id))
}

/// String field of a JSON object, `""` when missing or not a string.
pub(crate) fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Case-insensitive string equality for ARM enum values.
pub(crate) fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Last path segment of an ARM resource id (the resource name).
pub(crate) fn resource_name(id: &str) -> &str {
    id.rsplit('/').next().unwrap_or(id)
}

/// Shorten a list for `current_value`: first `n` items then "and N more".
pub(crate) fn summarise(items: &[String], n: usize) -> String {
    if items.len() <= n {
        items.join(", ")
    } else {
        format!("{} and {} more", items[..n].join(", "), items.len() - n)
    }
}

const SUBSCRIPTIONS_KQL: &str = "resourcecontainers \
| where type =~ 'microsoft.resources/subscriptions' \
| project subscriptionId, name, state = tostring(properties.state)";

const MANAGEMENT_GROUPS_KQL: &str = "resourcecontainers \
| where type =~ 'microsoft.management/managementgroups' \
| project name, displayName = tostring(properties.displayName)";

pub(crate) fn parse_subscriptions(rows: &[Value]) -> Vec<Subscription> {
    let mut subs: Vec<Subscription> = rows
        .iter()
        .filter_map(|r| {
            let id = str_at(r, "subscriptionId");
            (!id.is_empty()).then(|| Subscription {
                id: id.to_string(),
                name: str_at(r, "name").to_string(),
                state: str_at(r, "state").to_string(),
            })
        })
        .collect();
    subs.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    subs
}

const ACCESS_CONSENT_HINT: &str = "The signed-in app needs the Azure Service Management \
`user_impersonation` delegated permission and the signed-in user (or the app's service principal) \
needs Reader at the root management group (or on each subscription). Register an app with that API \
permission and pass --client-id, or skip the azure module.";

fn access_unknown(registry: &ControlRegistry, error: impl std::fmt::Display) -> Finding {
    let mut f = Finding::unknown(
        "AZ-ACCESS-001",
        "AZURE",
        "Azure access",
        "Azure Resource Manager reachability",
        "Whether the assessment can read Azure subscriptions through Azure Resource Manager.",
        error,
    );
    f.severity = registry.get_severity("AZ-ACCESS-001");
    f.framework_mappings = registry.mappings("AZ-ACCESS-001");
    f.remediation = format!(
        "{ACCESS_CONSENT_HINT} Every AZ-*, LOG-DIAG/RETENTION/SENTINEL and AZ-BACKUP check is \
unassessed until this is resolved."
    );
    f
}

fn access_finding(
    registry: &ControlRegistry,
    subs: &[Subscription],
    management_groups: &[Value],
) -> Finding {
    let names: Vec<String> = subs
        .iter()
        .map(|s| {
            if eq_ci(&s.state, "Enabled") || s.state.is_empty() {
                s.name.clone()
            } else {
                format!("{} [{}]", s.name, s.state)
            }
        })
        .collect();
    let mg_names: Vec<String> = management_groups
        .iter()
        .map(|m| {
            let d = str_at(m, "displayName");
            if d.is_empty() {
                str_at(m, "name").to_string()
            } else {
                d.to_string()
            }
        })
        .collect();
    let builder = check(
        registry,
        "AZ-ACCESS-001",
        "AZURE",
        "Azure access",
        "Readable subscriptions and management groups",
        "Azure subscriptions and management groups visible to the assessment identity through Resource Graph. \
Checks below cover only these subscriptions; Reader at the root management group makes the view complete.",
    )
    .details(json!({
        "subscriptions": subs.iter().map(|s| json!({"id": s.id, "name": s.name, "state": s.state})).collect::<Vec<_>>(),
        "managementGroups": management_groups,
    }));
    if subs.is_empty() {
        return builder
            .status(FindingStatus::Warning)
            .current_value(
                "Azure Resource Manager accepted the token but Resource Graph returned no subscriptions. \
Subscription-scoped checks (RBAC, Defender, Key Vault, storage, backup, Sentinel) were skipped.",
            )
            .expected_value("At least one readable subscription, ideally Reader at the root management group")
            .remediation(
                "Grant the assessment identity Reader at the root management group (Tenant Root Group) so \
every subscription is visible, then run the scan again.",
            )
            .build();
    }
    builder
        .status(FindingStatus::Info)
        .current_value(format!(
            "{} subscription(s): {}. {} management group(s){}{}",
            subs.len(),
            summarise(&names, 10),
            mg_names.len(),
            if mg_names.is_empty() { "" } else { ": " },
            summarise(&mg_names, 10)
        ))
        .expected_value("Every subscription in the tenant is visible to the assessment")
        .remediation(
            "If subscriptions are missing, grant Reader at the root management group so the assessment sees all of them.",
        )
        .build()
}

#[async_trait]
impl AssessmentModule for AzureModule {
    fn name(&self) -> &str {
        "Azure"
    }

    fn description(&self) -> &str {
        "Azure subscriptions, RBAC, Defender for Cloud, Key Vault, storage, backup and logging"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        _tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();

        // Checks that don't touch ARM run regardless of Azure consent.
        record_one(
            &mut findings,
            backup::m365_backup(graph, registry).await,
            "BCK-M365-001",
            "BACKUP",
            "Microsoft 365 Backup",
            "Protection policies for Exchange, SharePoint and OneDrive",
        );

        let jx = JunctionGateway::new(graph).context("building the Junction gateway")?;
        record_one(
            &mut findings,
            power_platform::governance(&jx, registry).await,
            "PP-GOVERNANCE-001",
            "POWERPLATFORM",
            "Power Platform governance",
            "Rule-based data policies",
        );

        // One Unknown for the whole ARM surface when the token can't be had.
        if let Err(e) = graph
            .auth()
            .get_resource_token(Resource::AzureResourceManager)
            .await
        {
            tracing::warn!("Azure Resource Manager token unavailable: {e}");
            findings.push(access_unknown(registry, e));
            record_one(
                &mut findings,
                logging::detections(graph, registry, None).await,
                "LOG-DETECT-001",
                "LOGGING",
                "Detection rules",
                "Enabled analytics and custom detection rules",
            );
            return Ok(finish(self.name(), findings, start));
        }

        let mut ctx = Ctx {
            graph,
            jx: &jx,
            registry,
            subscriptions: Vec::new(),
        };
        let subs = match ctx.resource_graph(SUBSCRIPTIONS_KQL).await {
            Ok(rows) => parse_subscriptions(&rows),
            Err(e) => {
                tracing::warn!("Resource Graph subscription discovery failed: {e}");
                findings.push(access_unknown(registry, e));
                return Ok(finish(self.name(), findings, start));
            }
        };
        let management_groups = ctx
            .resource_graph(MANAGEMENT_GROUPS_KQL)
            .await
            .unwrap_or_default();
        findings.push(access_finding(registry, &subs, &management_groups));
        ctx.subscriptions = subs;

        // Tenant-scoped reads work without any subscription.
        record_one(
            &mut findings,
            rbac::root_scope_uaa(&ctx).await,
            "AZ-RBAC-002",
            "AZURE",
            "Azure RBAC",
            "User Access Administrator at root scope",
        );
        let diag = logging::entra_diagnostics(&ctx).await;
        let workspace_targets = diag.as_ref().ok().map(|(_, ws)| ws.clone());
        record_one(
            &mut findings,
            diag.map(|(f, _)| f),
            "LOG-DIAG-001",
            "LOGGING",
            "Entra ID diagnostic settings",
            "Sign-in and audit log export",
        );

        if ctx.subscriptions.is_empty() {
            record_one(
                &mut findings,
                logging::detections(graph, registry, None).await,
                "LOG-DETECT-001",
                "LOGGING",
                "Detection rules",
                "Enabled analytics and custom detection rules",
            );
            return Ok(finish(self.name(), findings, start));
        }

        record_one(
            &mut findings,
            rbac::standing_privileged_users(&ctx).await,
            "AZ-RBAC-001",
            "AZURE",
            "Azure RBAC",
            "Permanent Owner / User Access Administrator for users",
        );
        record_one(
            &mut findings,
            defender::plans(&ctx).await,
            "AZ-DEFENDER-001",
            "AZURE",
            "Defender for Cloud",
            "Defender plans on subscriptions with matching resources",
        );
        record_one(
            &mut findings,
            defender::posture(&ctx).await,
            "AZ-DEFENDER-002",
            "AZURE",
            "Defender for Cloud",
            "Secure score and unhealthy high-severity recommendations",
        );
        let vaults = keyvault::vaults(&ctx).await;
        record_one(
            &mut findings,
            vaults
                .as_ref()
                .map_err(|e| anyhow::anyhow!("{e}"))
                .map(|v| keyvault::configuration(&ctx, v)),
            "AZ-KV-001",
            "AZURE",
            "Key Vault",
            "RBAC model, purge protection and network restriction",
        );
        record_one(
            &mut findings,
            match &vaults {
                Ok(v) => keyvault::diagnostics(&ctx, v).await,
                Err(e) => Err(anyhow::anyhow!("{e}")),
            },
            "AZ-KV-002",
            "AZURE",
            "Key Vault",
            "Diagnostic settings per vault",
        );
        let storage = ctx.resource_graph(workloads::STORAGE_KQL).await;
        record_one(
            &mut findings,
            match &storage {
                Ok(s) => workloads::managed_identity(&ctx, s).await,
                Err(e) => Err(anyhow::anyhow!("{e}")),
            },
            "AZ-MI-001",
            "AZURE",
            "Workload identity",
            "Shared Key access and managed identities",
        );
        record_one(
            &mut findings,
            match &storage {
                Ok(s) => workloads::public_exposure(&ctx, s).await,
                Err(e) => Err(anyhow::anyhow!("{e}")),
            },
            "AZ-PUBLIC-001",
            "AZURE",
            "Public exposure",
            "Anonymous blob access and public network access on PaaS data services",
        );
        record_one(
            &mut findings,
            backup::azure_backup_vaults(&ctx).await,
            "AZ-BACKUP-001",
            "BACKUP",
            "Azure Backup",
            "Vault soft delete, immutability and multi-user authorisation",
        );
        record_one(
            &mut findings,
            logging::workspace_retention(&ctx, workspace_targets.as_ref()).await,
            "LOG-RETENTION-001",
            "LOGGING",
            "Log Analytics retention",
            "Workspace retention for Entra log targets",
        );
        let sentinel = logging::sentinel(&ctx).await;
        let sentinel_rules = sentinel.as_ref().ok().map(|(_, r)| r.clone());
        record_one(
            &mut findings,
            sentinel.map(|(f, _)| f),
            "LOG-SENTINEL-001",
            "LOGGING",
            "Microsoft Sentinel",
            "Data connectors and enabled analytics rules",
        );
        record_one(
            &mut findings,
            logging::detections(graph, registry, sentinel_rules.as_deref()).await,
            "LOG-DETECT-001",
            "LOGGING",
            "Detection rules",
            "Enabled analytics and custom detection rules",
        );

        Ok(finish(self.name(), findings, start))
    }
}

fn finish(name: &str, findings: Vec<Finding>, start: std::time::Instant) -> ModuleResult {
    ModuleResult {
        module_name: name.to_string(),
        findings,
        raw_data: Value::Null,
        error: None,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriptions_parse_and_sort_by_name() {
        let rows = vec![
            json!({"subscriptionId": "b", "name": "Prod", "state": "Enabled"}),
            json!({"subscriptionId": "a", "name": "Dev", "state": "Disabled"}),
            json!({"name": "no id"}),
        ];
        let subs = parse_subscriptions(&rows);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].name, "Dev");
        assert_eq!(subs[1].id, "b");
    }

    #[test]
    fn summarise_truncates() {
        let items: Vec<String> = (1..=5).map(|i| i.to_string()).collect();
        assert_eq!(summarise(&items, 3), "1, 2, 3 and 2 more");
        assert_eq!(summarise(&items[..2], 3), "1, 2");
    }

    #[test]
    fn resource_name_is_last_segment() {
        assert_eq!(
            resource_name(
                "/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
            ),
            "kv1"
        );
    }
}
