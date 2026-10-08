//! AZ-KV-001 / AZ-KV-002: Key Vault permission model, purge protection, network restriction and
//! diagnostic settings.

use anyhow::Result;
use serde_json::{json, Value};

use super::{check, eq_ci, resource_name, str_at, summarise, Ctx};
use crate::assessment::finding::{Finding, FindingStatus};

const VAULTS_KQL: &str = "resources \
| where type =~ 'microsoft.keyvault/vaults' \
| project id, name, subscriptionId, \
enableRbacAuthorization = properties.enableRbacAuthorization, \
enablePurgeProtection = properties.enablePurgeProtection, \
enableSoftDelete = properties.enableSoftDelete, \
publicNetworkAccess = tostring(properties.publicNetworkAccess), \
defaultAction = tostring(properties.networkAcls.defaultAction)";

/// How many vaults get a per-vault diagnostic-settings read before sampling stops.
const DIAG_VAULT_CAP: usize = 50;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct VaultGaps {
    pub total: usize,
    pub access_policies: Vec<String>,
    pub no_purge_protection: Vec<String>,
    pub soft_delete_off: Vec<String>,
    pub public_network: Vec<String>,
}

impl VaultGaps {
    pub fn compliant(&self) -> bool {
        self.access_policies.is_empty()
            && self.no_purge_protection.is_empty()
            && self.public_network.is_empty()
    }
}

/// Network restricted when public access is disabled or the firewall denies by default.
pub(crate) fn network_restricted(vault: &Value) -> bool {
    eq_ci(str_at(vault, "publicNetworkAccess"), "Disabled")
        || eq_ci(str_at(vault, "defaultAction"), "Deny")
}

pub(crate) fn evaluate_vaults(vaults: &[Value]) -> VaultGaps {
    let mut gaps = VaultGaps {
        total: vaults.len(),
        ..Default::default()
    };
    for v in vaults {
        let name = str_at(v, "name").to_string();
        if v["enableRbacAuthorization"].as_bool() != Some(true) {
            gaps.access_policies.push(name.clone());
        }
        if v["enablePurgeProtection"].as_bool() != Some(true) {
            gaps.no_purge_protection.push(name.clone());
        }
        // Soft delete is on by default for new vaults; `null` means on, explicit `false` is the gap.
        if v["enableSoftDelete"].as_bool() == Some(false) {
            gaps.soft_delete_off.push(name.clone());
        }
        if !network_restricted(v) {
            gaps.public_network.push(name);
        }
    }
    gaps
}

pub(crate) async fn vaults(ctx: &Ctx<'_>) -> Result<Vec<Value>> {
    ctx.resource_graph(VAULTS_KQL).await
}

pub(crate) fn configuration(ctx: &Ctx<'_>, vaults: &[Value]) -> Finding {
    let gaps = evaluate_vaults(vaults);
    let builder = check(
        ctx.registry,
        "AZ-KV-001",
        "AZURE",
        "Key Vault",
        "RBAC model, purge protection and network restriction",
        "Key vaults should use the Azure RBAC permission model, have purge protection enabled and restrict network access \
(public network access disabled or firewall default action Deny). Vault access policies are coarse and hard to audit; \
without purge protection a deleted vault or key is gone for good.",
    )
    .expected_value(
        "enableRbacAuthorization = true, enablePurgeProtection = true, publicNetworkAccess = Disabled or networkAcls.defaultAction = Deny",
    )
    .remediation(
        "Migrate vaults to Azure RBAC (Key Vault > Access configuration), enable purge protection, restrict networking with \
private endpoints or firewall rules, and enforce with the built-in Azure Policy definitions for Key Vault.",
    );
    if vaults.is_empty() {
        return builder
            .status(FindingStatus::Info)
            .current_value("No key vaults in the readable subscriptions.")
            .build();
    }
    let mut parts = Vec::new();
    if !gaps.access_policies.is_empty() {
        parts.push(format!(
            "{} using access policies ({})",
            gaps.access_policies.len(),
            summarise(&gaps.access_policies, 5)
        ));
    }
    if !gaps.no_purge_protection.is_empty() {
        parts.push(format!(
            "{} without purge protection ({})",
            gaps.no_purge_protection.len(),
            summarise(&gaps.no_purge_protection, 5)
        ));
    }
    if !gaps.public_network.is_empty() {
        parts.push(format!(
            "{} open to public networks ({})",
            gaps.public_network.len(),
            summarise(&gaps.public_network, 5)
        ));
    }
    if !gaps.soft_delete_off.is_empty() {
        parts.push(format!(
            "{} with soft delete off ({})",
            gaps.soft_delete_off.len(),
            summarise(&gaps.soft_delete_off, 5)
        ));
    }
    let mut affected: Vec<String> = gaps
        .access_policies
        .iter()
        .chain(&gaps.no_purge_protection)
        .chain(&gaps.public_network)
        .chain(&gaps.soft_delete_off)
        .cloned()
        .collect();
    affected.sort();
    affected.dedup();
    builder
        .status(if gaps.compliant() {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        })
        .current_value(if gaps.compliant() {
            format!(
                "All {} key vault(s) use Azure RBAC, have purge protection and restrict network access.",
                gaps.total
            )
        } else {
            format!("Of {} key vault(s): {}.", gaps.total, parts.join("; "))
        })
        .affected_resources(affected)
        .details(json!({
            "vaults": gaps.total,
            "accessPolicyModel": gaps.access_policies,
            "noPurgeProtection": gaps.no_purge_protection,
            "publicNetwork": gaps.public_network,
            "softDeleteOff": gaps.soft_delete_off,
        }))
        .build()
}

/// A diagnostic setting counts when at least one log category (or category group) is enabled and the
/// setting has a destination.
pub(crate) fn has_log_destination(settings: &[Value]) -> bool {
    settings.iter().any(|s| {
        let p = &s["properties"];
        let has_dest = [
            "workspaceId",
            "storageAccountId",
            "eventHubAuthorizationRuleId",
            "marketplacePartnerId",
        ]
        .iter()
        .any(|k| !str_at(p, k).is_empty());
        let has_log = p["logs"]
            .as_array()
            .map(|logs| logs.iter().any(|l| l["enabled"].as_bool() == Some(true)))
            .unwrap_or(false);
        has_dest && has_log
    })
}

pub(crate) async fn diagnostics(ctx: &Ctx<'_>, vaults: &[Value]) -> Result<Finding> {
    let builder = check(
        ctx.registry,
        "AZ-KV-002",
        "AZURE",
        "Key Vault",
        "Diagnostic settings per vault",
        "Each key vault should send its AuditEvent logs to a Log Analytics workspace, storage account or event hub so secret \
and key access is recorded.",
    )
    .expected_value("Every vault has a diagnostic setting with log categories enabled and a destination")
    .remediation(
        "Add a diagnostic setting on each vault (Monitoring > Diagnostic settings) for the audit log category group to the \
central Log Analytics workspace, or deploy it through Azure Policy (DeployIfNotExists).",
    );
    if vaults.is_empty() {
        return Ok(builder
            .status(FindingStatus::Info)
            .current_value("No key vaults in the readable subscriptions.")
            .build());
    }
    let sampled: Vec<&Value> = vaults.iter().take(DIAG_VAULT_CAP).collect();
    let mut without: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for v in &sampled {
        let id = str_at(v, "id");
        let url = format!(
            "{id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
        );
        match ctx.arm_get_all(&url).await {
            Ok(settings) => {
                if !has_log_destination(&settings) {
                    without.push(resource_name(id).to_string());
                }
            }
            Err(e) => {
                tracing::debug!("diagnostic settings for {id}: {e}");
                errors.push(resource_name(id).to_string());
            }
        }
    }
    if errors.len() == sampled.len() {
        anyhow::bail!(
            "diagnostic settings could not be read for any of {} vault(s); the identity needs Reader on the vaults (Microsoft.Insights/diagnosticSettings/read)",
            sampled.len()
        );
    }
    let status = if without.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };
    let mut current = if without.is_empty() {
        format!(
            "All {} checked key vault(s) have a diagnostic setting with logs and a destination.",
            sampled.len() - errors.len()
        )
    } else {
        format!(
            "{} of {} checked key vault(s) have no diagnostic setting with logs enabled: {}.",
            without.len(),
            sampled.len() - errors.len(),
            summarise(&without, 10)
        )
    };
    if vaults.len() > DIAG_VAULT_CAP {
        current.push_str(&format!(
            " Only the first {DIAG_VAULT_CAP} of {} vaults were checked.",
            vaults.len()
        ));
    }
    if !errors.is_empty() {
        current.push_str(&format!(
            " {} vault(s) could not be read: {}.",
            errors.len(),
            summarise(&errors, 5)
        ));
    }
    Ok(builder
        .status(status)
        .current_value(current)
        .affected_resources(without.clone())
        .details(json!({
            "checked": sampled.len(),
            "total": vaults.len(),
            "withoutDiagnostics": without,
            "unreadable": errors,
        }))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_gaps_per_property() {
        let vaults = vec![
            json!({"name": "good", "enableRbacAuthorization": true, "enablePurgeProtection": true,
                "publicNetworkAccess": "Disabled", "defaultAction": "Allow"}),
            json!({"name": "fw", "enableRbacAuthorization": true, "enablePurgeProtection": true,
                "publicNetworkAccess": "Enabled", "defaultAction": "Deny"}),
            json!({"name": "legacy", "enableRbacAuthorization": null, "enablePurgeProtection": null,
                "enableSoftDelete": false, "publicNetworkAccess": "", "defaultAction": "Allow"}),
        ];
        let gaps = evaluate_vaults(&vaults);
        assert_eq!(gaps.total, 3);
        assert_eq!(gaps.access_policies, vec!["legacy"]);
        assert_eq!(gaps.no_purge_protection, vec!["legacy"]);
        assert_eq!(gaps.public_network, vec!["legacy"]);
        assert_eq!(gaps.soft_delete_off, vec!["legacy"]);
        assert!(!gaps.compliant());
        assert!(evaluate_vaults(&vaults[..2]).compliant());
    }

    #[test]
    fn diagnostic_setting_needs_logs_and_destination() {
        let none: Vec<Value> = vec![];
        assert!(!has_log_destination(&none));
        let no_dest =
            vec![json!({"properties": {"logs": [{"category": "AuditEvent", "enabled": true}]}})];
        assert!(!has_log_destination(&no_dest));
        let disabled = vec![
            json!({"properties": {"workspaceId": "/w", "logs": [{"category": "AuditEvent", "enabled": false}]}}),
        ];
        assert!(!has_log_destination(&disabled));
        let ok = vec![
            json!({"properties": {"workspaceId": "/w", "logs": [{"categoryGroup": "audit", "enabled": true}]}}),
        ];
        assert!(has_log_destination(&ok));
    }
}
