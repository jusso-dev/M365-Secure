//! AZ-MI-001 / AZ-PUBLIC-001: workload authentication (Shared Key, managed identities) and public
//! exposure of storage and PaaS data services.

use anyhow::Result;
use serde_json::{json, Value};

use super::{check, eq_ci, str_at, summarise, Ctx};
use crate::assessment::finding::{Finding, FindingStatus};

pub(crate) const STORAGE_KQL: &str = "resources \
| where type =~ 'microsoft.storage/storageaccounts' \
| project id, name, subscriptionId, \
allowSharedKeyAccess = properties.allowSharedKeyAccess, \
allowBlobPublicAccess = properties.allowBlobPublicAccess, \
publicNetworkAccess = tostring(properties.publicNetworkAccess), \
defaultAction = tostring(properties.networkAcls.defaultAction)";

const SITES_KQL: &str = "resources \
| where type =~ 'microsoft.web/sites' \
| project id, name, kind, identityType = tostring(identity.type)";

const DATA_SERVICES_KQL: &str = "resources \
| where type in~ ('microsoft.sql/servers', 'microsoft.documentdb/databaseaccounts', \
'microsoft.dbforpostgresql/flexibleservers', 'microsoft.dbforpostgresql/servers', \
'microsoft.dbformysql/flexibleservers', 'microsoft.dbformysql/servers', 'microsoft.dbformariadb/servers', \
'microsoft.synapse/workspaces', 'microsoft.cache/redis') \
| project id, name, type, \
publicNetworkAccess = iff(isnotempty(tostring(properties.publicNetworkAccess)), \
tostring(properties.publicNetworkAccess), tostring(properties.network.publicNetworkAccess))";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct IdentityGaps {
    pub storage_total: usize,
    pub shared_key_allowed: Vec<String>,
    pub sites_total: usize,
    pub sites_without_identity: Vec<String>,
}

impl IdentityGaps {
    pub fn compliant(&self) -> bool {
        self.shared_key_allowed.is_empty() && self.sites_without_identity.is_empty()
    }
    pub fn nothing_to_check(&self) -> bool {
        self.storage_total == 0 && self.sites_total == 0
    }
}

/// Shared Key is allowed unless the account says `false`; a site has an identity unless `identity.type`
/// is empty or `None`.
pub(crate) fn evaluate_identity(storage: &[Value], sites: &[Value]) -> IdentityGaps {
    IdentityGaps {
        storage_total: storage.len(),
        shared_key_allowed: storage
            .iter()
            .filter(|s| s["allowSharedKeyAccess"].as_bool() != Some(false))
            .map(|s| str_at(s, "name").to_string())
            .collect(),
        sites_total: sites.len(),
        sites_without_identity: sites
            .iter()
            .filter(|s| {
                let t = str_at(s, "identityType");
                t.is_empty() || eq_ci(t, "None")
            })
            .map(|s| str_at(s, "name").to_string())
            .collect(),
    }
}

pub(crate) async fn managed_identity(ctx: &Ctx<'_>, storage: &[Value]) -> Result<Finding> {
    let sites = ctx.resource_graph(SITES_KQL).await?;
    let gaps = evaluate_identity(storage, &sites);
    let builder = check(
        ctx.registry,
        "AZ-MI-001",
        "AZURE",
        "Workload identity",
        "Shared Key access and managed identities",
        "Workloads should authenticate with managed identities rather than stored keys: storage accounts should disallow Shared \
Key authorisation and App Service / Functions apps should have a managed identity assigned.",
    )
    .expected_value("allowSharedKeyAccess = false on every storage account; identity.type != None on every web app")
    .remediation(
        "Enable system- or user-assigned managed identities on App Service and Functions and grant them scoped RBAC roles, move \
clients to Entra authentication, then set 'Allow storage account key access' to Disabled on each storage account.",
    );
    if gaps.nothing_to_check() {
        return Ok(builder
            .status(FindingStatus::Info)
            .current_value("No storage accounts or App Service / Functions apps in the readable subscriptions.")
            .build());
    }
    let mut affected: Vec<String> = gaps.shared_key_allowed.clone();
    affected.extend(gaps.sites_without_identity.iter().cloned());
    Ok(builder
        .status(if gaps.compliant() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .current_value(format!(
            "{} of {} storage account(s) allow Shared Key access{}; {} of {} web app(s) have no managed identity{}.",
            gaps.shared_key_allowed.len(),
            gaps.storage_total,
            if gaps.shared_key_allowed.is_empty() {
                String::new()
            } else {
                format!(" ({})", summarise(&gaps.shared_key_allowed, 5))
            },
            gaps.sites_without_identity.len(),
            gaps.sites_total,
            if gaps.sites_without_identity.is_empty() {
                String::new()
            } else {
                format!(" ({})", summarise(&gaps.sites_without_identity, 5))
            },
        ))
        .affected_resources(affected)
        .details(json!({
            "storageAccounts": gaps.storage_total,
            "sharedKeyAllowed": gaps.shared_key_allowed,
            "webApps": gaps.sites_total,
            "webAppsWithoutIdentity": gaps.sites_without_identity,
        }))
        .build())
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ExposureGaps {
    pub storage_total: usize,
    pub blob_public_allowed: Vec<String>,
    pub storage_network_open: Vec<String>,
    pub data_services_total: usize,
    pub data_services_public: Vec<String>,
}

impl ExposureGaps {
    pub fn compliant(&self) -> bool {
        self.blob_public_allowed.is_empty()
            && self.storage_network_open.is_empty()
            && self.data_services_public.is_empty()
    }
    pub fn nothing_to_check(&self) -> bool {
        self.storage_total == 0 && self.data_services_total == 0
    }
}

/// Storage network is open when public access is Enabled (or unset, the default) and the firewall
/// default action is not Deny.
pub(crate) fn storage_network_open(account: &Value) -> bool {
    let pna = str_at(account, "publicNetworkAccess");
    let enabled = pna.is_empty() || eq_ci(pna, "Enabled");
    enabled && !eq_ci(str_at(account, "defaultAction"), "Deny")
}

pub(crate) fn evaluate_exposure(storage: &[Value], data_services: &[Value]) -> ExposureGaps {
    ExposureGaps {
        storage_total: storage.len(),
        // Anonymous blob access must be explicitly off; unset means the pre-2023 default (allowed).
        blob_public_allowed: storage
            .iter()
            .filter(|s| s["allowBlobPublicAccess"].as_bool() != Some(false))
            .map(|s| str_at(s, "name").to_string())
            .collect(),
        storage_network_open: storage
            .iter()
            .filter(|s| storage_network_open(s))
            .map(|s| str_at(s, "name").to_string())
            .collect(),
        data_services_total: data_services.len(),
        // These services default to a public endpoint, so unset counts as Enabled.
        data_services_public: data_services
            .iter()
            .filter(|d| {
                let pna = str_at(d, "publicNetworkAccess");
                pna.is_empty() || eq_ci(pna, "Enabled")
            })
            .map(|d| {
                format!(
                    "{} ({})",
                    str_at(d, "name"),
                    str_at(d, "type").rsplit('/').next().unwrap_or("")
                )
            })
            .collect(),
    }
}

pub(crate) async fn public_exposure(ctx: &Ctx<'_>, storage: &[Value]) -> Result<Finding> {
    let data_services = ctx.resource_graph(DATA_SERVICES_KQL).await?;
    let gaps = evaluate_exposure(storage, &data_services);
    let builder = check(
        ctx.registry,
        "AZ-PUBLIC-001",
        "AZURE",
        "Public exposure",
        "Anonymous blob access and public network access on PaaS data services",
        "Storage accounts should disallow anonymous blob access and restrict public network access; SQL, Cosmos DB, PostgreSQL, \
MySQL, Synapse and Redis should have public network access disabled (private endpoints or an explicit firewall allow-list).",
    )
    .expected_value(
        "allowBlobPublicAccess = false and (publicNetworkAccess = Disabled or networkAcls.defaultAction = Deny) on storage; \
publicNetworkAccess = Disabled on data services",
    )
    .remediation(
        "Set 'Allow Blob anonymous access' to Disabled and the storage firewall default to Deny (with private endpoints or \
selected networks), disable public network access on database and cache services behind private endpoints, and enforce both \
with Azure Policy deny effects.",
    );
    if gaps.nothing_to_check() {
        return Ok(builder
            .status(FindingStatus::Info)
            .current_value(
                "No storage accounts or PaaS data services in the readable subscriptions.",
            )
            .build());
    }
    let mut parts = Vec::new();
    if !gaps.blob_public_allowed.is_empty() {
        parts.push(format!(
            "{} storage account(s) allow anonymous blob access ({})",
            gaps.blob_public_allowed.len(),
            summarise(&gaps.blob_public_allowed, 5)
        ));
    }
    if !gaps.storage_network_open.is_empty() {
        parts.push(format!(
            "{} storage account(s) accept traffic from all networks ({})",
            gaps.storage_network_open.len(),
            summarise(&gaps.storage_network_open, 5)
        ));
    }
    if !gaps.data_services_public.is_empty() {
        parts.push(format!(
            "{} data service(s) have public network access enabled ({})",
            gaps.data_services_public.len(),
            summarise(&gaps.data_services_public, 5)
        ));
    }
    let mut affected: Vec<String> = gaps
        .blob_public_allowed
        .iter()
        .chain(&gaps.storage_network_open)
        .chain(&gaps.data_services_public)
        .cloned()
        .collect();
    affected.sort();
    affected.dedup();
    Ok(builder
        .status(if gaps.compliant() {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        })
        .current_value(if gaps.compliant() {
            format!(
                "All {} storage account(s) and {} data service(s) are closed to anonymous and public network access.",
                gaps.storage_total, gaps.data_services_total
            )
        } else {
            format!(
                "Of {} storage account(s) and {} data service(s): {}.",
                gaps.storage_total,
                gaps.data_services_total,
                parts.join("; ")
            )
        })
        .affected_resources(affected)
        .details(json!({
            "storageAccounts": gaps.storage_total,
            "blobPublicAccessAllowed": gaps.blob_public_allowed,
            "storageNetworkOpen": gaps.storage_network_open,
            "dataServices": gaps.data_services_total,
            "dataServicesPublic": gaps.data_services_public,
        }))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_gaps() {
        let storage = vec![
            json!({"name": "locked", "allowSharedKeyAccess": false}),
            json!({"name": "default", "allowSharedKeyAccess": null}),
            json!({"name": "open", "allowSharedKeyAccess": true}),
        ];
        let sites = vec![
            json!({"name": "api", "kind": "app", "identityType": "SystemAssigned"}),
            json!({"name": "legacy", "kind": "functionapp", "identityType": "None"}),
            json!({"name": "unset", "kind": "app", "identityType": ""}),
        ];
        let gaps = evaluate_identity(&storage, &sites);
        assert_eq!(gaps.shared_key_allowed, vec!["default", "open"]);
        assert_eq!(gaps.sites_without_identity, vec!["legacy", "unset"]);
        assert!(!gaps.compliant());
        assert!(evaluate_identity(&storage[..1], &sites[..1]).compliant());
        assert!(evaluate_identity(&[], &[]).nothing_to_check());
    }

    #[test]
    fn exposure_gaps() {
        let storage = vec![
            json!({"name": "private", "allowBlobPublicAccess": false, "publicNetworkAccess": "Disabled", "defaultAction": "Allow"}),
            json!({"name": "firewalled", "allowBlobPublicAccess": false, "publicNetworkAccess": "Enabled", "defaultAction": "Deny"}),
            json!({"name": "anon", "allowBlobPublicAccess": true, "publicNetworkAccess": "", "defaultAction": "Allow"}),
            json!({"name": "unset", "publicNetworkAccess": "Enabled", "defaultAction": "Allow"}),
        ];
        let data = vec![
            json!({"name": "sql1", "type": "microsoft.sql/servers", "publicNetworkAccess": "Disabled"}),
            json!({"name": "cosmos1", "type": "microsoft.documentdb/databaseaccounts", "publicNetworkAccess": "Enabled"}),
            json!({"name": "pg1", "type": "microsoft.dbforpostgresql/flexibleservers", "publicNetworkAccess": ""}),
        ];
        let gaps = evaluate_exposure(&storage, &data);
        assert_eq!(gaps.blob_public_allowed, vec!["anon", "unset"]);
        assert_eq!(gaps.storage_network_open, vec!["anon", "unset"]);
        assert_eq!(
            gaps.data_services_public,
            vec!["cosmos1 (databaseaccounts)", "pg1 (flexibleservers)"]
        );
        assert!(!gaps.compliant());
        assert!(evaluate_exposure(&storage[..2], &data[..1]).compliant());
    }
}
