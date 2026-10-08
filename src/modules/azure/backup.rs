//! AZ-BACKUP-001: Azure Backup vault immutability, soft delete and multi-user authorisation.
//! BCK-M365-001: Microsoft 365 Backup protection policies (Graph, no ARM needed).

use anyhow::Result;
use serde_json::{json, Value};

use super::{check, eq_ci, resource_name, str_at, summarise, Ctx};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

const VAULTS_KQL: &str = "resources \
| where type in~ ('microsoft.recoveryservices/vaults', 'microsoft.dataprotection/backupvaults') \
| project id, name, type = tolower(type), subscriptionId, properties";

const VAULTCONFIG_CAP: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultPosture {
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    /// Normalised: `AlwaysON`, `Enabled`, `Disabled` or `Unknown`.
    pub soft_delete: String,
    /// `Locked`, `Unlocked`, `Disabled` or `Unknown`.
    pub immutability: String,
    pub multi_user_authorization: bool,
}

impl VaultPosture {
    pub fn soft_delete_always_on(&self) -> bool {
        eq_ci(&self.soft_delete, "AlwaysON")
    }
    pub fn immutability_locked(&self) -> bool {
        eq_ci(&self.immutability, "Locked")
    }
    pub fn compliant(&self) -> bool {
        self.soft_delete_always_on() && self.immutability_locked()
    }
}

fn normalise_soft_delete(state: &str) -> String {
    if eq_ci(state, "AlwaysON") || eq_ci(state, "AlwaysOn") {
        "AlwaysON".to_string()
    } else if eq_ci(state, "Enabled") || eq_ci(state, "On") {
        "Enabled".to_string()
    } else if eq_ci(state, "Disabled") || eq_ci(state, "Off") {
        "Disabled".to_string()
    } else if state.is_empty() {
        "Unknown".to_string()
    } else {
        state.to_string()
    }
}

/// Posture from the Resource Graph row plus, for Recovery Services vaults, the `backupconfig/vaultconfig`
/// document (which carries `softDeleteFeatureState` when `securitySettings` does not).
pub(crate) fn posture(vault: &Value, vaultconfig: Option<&Value>) -> VaultPosture {
    let kind = if str_at(vault, "type").contains("dataprotection") {
        "Backup vault"
    } else {
        "Recovery Services vault"
    };
    let security = &vault["properties"]["securitySettings"];
    let soft_delete_settings = &security["softDeleteSettings"];
    let mut soft_delete = str_at(soft_delete_settings, "softDeleteState");
    if soft_delete.is_empty() {
        soft_delete = str_at(soft_delete_settings, "state");
    }
    if soft_delete.is_empty() {
        if let Some(cfg) = vaultconfig {
            soft_delete = str_at(&cfg["properties"], "softDeleteFeatureState");
            // Older vaults report Enabled with the state locked rather than AlwaysON.
            if eq_ci(soft_delete, "Enabled")
                && cfg["properties"]["isSoftDeleteFeatureStateEditable"].as_bool() == Some(false)
            {
                soft_delete = "AlwaysON";
            }
        }
    }
    let immutability = str_at(&security["immutabilitySettings"], "state");
    let mua = eq_ci(str_at(security, "multiUserAuthorization"), "Enabled")
        || vault["properties"]["resourceGuardOperationRequests"]
            .as_array()
            .is_some_and(|a| !a.is_empty());
    VaultPosture {
        id: str_at(vault, "id").to_string(),
        name: str_at(vault, "name").to_string(),
        kind,
        soft_delete: normalise_soft_delete(soft_delete),
        immutability: if immutability.is_empty() {
            "Disabled".to_string()
        } else {
            immutability.to_string()
        },
        multi_user_authorization: mua,
    }
}

pub(crate) fn evaluate_vaults(postures: &[VaultPosture]) -> FindingStatus {
    if postures.is_empty() {
        FindingStatus::Info
    } else if postures.iter().all(VaultPosture::compliant) {
        FindingStatus::Pass
    } else if postures
        .iter()
        .any(|p| p.soft_delete_always_on() || p.immutability_locked())
    {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    }
}

pub(crate) async fn azure_backup_vaults(ctx: &Ctx<'_>) -> Result<Finding> {
    let vaults = ctx.resource_graph(VAULTS_KQL).await?;
    let builder = check(
        ctx.registry,
        "AZ-BACKUP-001",
        "BACKUP",
        "Azure Backup",
        "Vault soft delete, immutability and multi-user authorisation",
        "Recovery Services and Backup vaults should have always-on soft delete, locked immutability and multi-user authorisation \
through Resource Guard, so one compromised subscription owner cannot delete recovery points before encrypting workloads.",
    )
    .expected_value("softDelete = AlwaysON and immutability = Locked on every vault; Resource Guard associated")
    .remediation(
        "On each vault open Properties > Security Settings: set soft delete to Always-on, enable immutability and lock it, and \
associate a Resource Guard held in a separate subscription (Multi-User Authorization). Enforce new vaults with Azure Policy.",
    );
    if vaults.is_empty() {
        return Ok(builder
            .status(FindingStatus::Info)
            .current_value("No Recovery Services or Backup vaults in the readable subscriptions (Azure Backup not in use).")
            .build());
    }
    let mut postures = Vec::new();
    let mut config_reads = 0usize;
    for v in &vaults {
        let needs_config = str_at(v, "type").contains("recoveryservices")
            && v["properties"]["securitySettings"]["softDeleteSettings"].is_null()
            && config_reads < VAULTCONFIG_CAP;
        let cfg = if needs_config {
            config_reads += 1;
            let url = format!(
                "{}/backupconfig/vaultconfig?api-version=2023-01-01",
                str_at(v, "id")
            );
            match ctx.arm_get(&url).await {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::debug!("vaultconfig for {}: {e}", resource_name(str_at(v, "id")));
                    None
                }
            }
        } else {
            None
        };
        postures.push(posture(v, cfg.as_ref()));
    }
    let status = evaluate_vaults(&postures);
    let gaps: Vec<String> = postures
        .iter()
        .filter(|p| !p.compliant())
        .map(|p| {
            format!(
                "{} (soft delete {}, immutability {}{})",
                p.name,
                p.soft_delete,
                p.immutability,
                if p.multi_user_authorization {
                    ", MUA"
                } else {
                    ""
                }
            )
        })
        .collect();
    let mua = postures
        .iter()
        .filter(|p| p.multi_user_authorization)
        .count();
    let current = if gaps.is_empty() {
        format!(
            "All {} vault(s) have always-on soft delete and locked immutability; {mua} use multi-user authorisation.",
            postures.len()
        )
    } else {
        format!(
            "{} of {} vault(s) lack always-on soft delete or locked immutability: {}. {mua} vault(s) use multi-user authorisation.",
            gaps.len(),
            postures.len(),
            summarise(&gaps, 8)
        )
    };
    Ok(builder
        .status(status)
        .current_value(current)
        .affected_resources(postures.iter().filter(|p| !p.compliant()).map(|p| p.name.clone()).collect())
        .details(json!({
            "vaults": postures.iter().map(|p| json!({
                "id": p.id, "name": p.name, "kind": p.kind, "softDelete": p.soft_delete,
                "immutability": p.immutability, "multiUserAuthorization": p.multi_user_authorization,
            })).collect::<Vec<_>>(),
        }))
        .build())
}

/// Workloads with at least one active protection policy.
pub(crate) fn active_workloads(
    exchange: &[Value],
    sharepoint: &[Value],
    onedrive: &[Value],
) -> (Vec<&'static str>, Vec<&'static str>) {
    let active = |policies: &[Value]| {
        policies
            .iter()
            .any(|p| eq_ci(str_at(p, "status"), "active"))
    };
    let mut on = Vec::new();
    let mut off = Vec::new();
    for (name, policies) in [
        ("Exchange", exchange),
        ("SharePoint", sharepoint),
        ("OneDrive", onedrive),
    ] {
        if active(policies) {
            on.push(name);
        } else {
            off.push(name);
        }
    }
    (on, off)
}

pub(crate) fn evaluate_m365(active: usize) -> FindingStatus {
    match active {
        3 => FindingStatus::Pass,
        0 => FindingStatus::Fail,
        _ => FindingStatus::Warning,
    }
}

pub(crate) async fn m365_backup(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let base = "/v1.0/solutions/backupRestore";
    let exchange = graph
        .get_all::<Value>(&format!("{base}/exchangeProtectionPolicies"))
        .await?;
    let sharepoint = graph
        .get_all::<Value>(&format!("{base}/sharePointProtectionPolicies"))
        .await?;
    let onedrive = graph
        .get_all::<Value>(&format!("{base}/oneDriveForBusinessProtectionPolicies"))
        .await?;
    let (on, off) = active_workloads(&exchange, &sharepoint, &onedrive);
    let status = evaluate_m365(on.len());
    Ok(check(
        registry,
        "BCK-M365-001",
        "BACKUP",
        "Microsoft 365 Backup",
        "Protection policies for Exchange, SharePoint and OneDrive",
        "Microsoft 365 Backup should hold an active protection policy for Exchange mailboxes, SharePoint sites and OneDrive \
accounts, giving a recovery path separate from recycle bins and version history that an attacker can purge. Third-party \
backup products are not visible here; whether every crown-jewel site and mailbox is covered needs the customer's list.",
    )
    .status(status)
    .current_value(match status {
        FindingStatus::Pass => "Active Microsoft 365 Backup policies exist for Exchange, SharePoint and OneDrive.".to_string(),
        FindingStatus::Fail => "No active Microsoft 365 Backup protection policy for any workload. If a third-party backup is in use, record it as attestation.".to_string(),
        _ => format!(
            "Active Microsoft 365 Backup policies for {}; none for {}.",
            on.join(", "),
            off.join(", ")
        ),
    })
    .expected_value("An active protection policy for each of Exchange, SharePoint and OneDrive")
    .remediation(
        "In the Microsoft 365 admin center enable Microsoft 365 Backup (pay-as-you-go billing) and create protection policies \
for crown-jewel mailboxes, sites and OneDrive accounts with rules that pick up new ones, or document the third-party backup.",
    )
    .details(json!({
        "exchangePolicies": exchange.len(),
        "sharePointPolicies": sharepoint.len(),
        "oneDrivePolicies": onedrive.len(),
        "activeWorkloads": on,
    }))
    .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_services_posture_from_security_settings() {
        let v = json!({
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv1",
            "name": "rsv1", "type": "microsoft.recoveryservices/vaults",
            "properties": {"securitySettings": {
                "softDeleteSettings": {"softDeleteState": "AlwaysON", "softDeleteRetentionPeriodInDays": 14},
                "immutabilitySettings": {"state": "Locked"},
                "multiUserAuthorization": "Enabled"
            }}
        });
        let p = posture(&v, None);
        assert!(p.compliant());
        assert!(p.multi_user_authorization);
        assert_eq!(p.kind, "Recovery Services vault");
    }

    #[test]
    fn recovery_services_posture_falls_back_to_vaultconfig() {
        let v = json!({"id": "/x/rsv2", "name": "rsv2", "type": "microsoft.recoveryservices/vaults", "properties": {}});
        let cfg = json!({"properties": {"softDeleteFeatureState": "Enabled", "isSoftDeleteFeatureStateEditable": false}});
        let p = posture(&v, Some(&cfg));
        assert_eq!(p.soft_delete, "AlwaysON");
        assert_eq!(p.immutability, "Disabled");
        assert!(!p.compliant());
        let cfg = json!({"properties": {"softDeleteFeatureState": "Enabled", "isSoftDeleteFeatureStateEditable": true}});
        assert_eq!(posture(&v, Some(&cfg)).soft_delete, "Enabled");
        assert_eq!(posture(&v, None).soft_delete, "Unknown");
    }

    #[test]
    fn backup_vault_posture_and_status() {
        let v = json!({"id": "/x/bv", "name": "bv", "type": "microsoft.dataprotection/backupvaults",
            "properties": {"securitySettings": {"softDeleteSettings": {"state": "AlwaysOn"},
            "immutabilitySettings": {"state": "Unlocked"}}, "resourceGuardOperationRequests": ["/rg/op"]}});
        let p = posture(&v, None);
        assert_eq!(p.kind, "Backup vault");
        assert!(p.soft_delete_always_on());
        assert!(!p.immutability_locked());
        assert!(p.multi_user_authorization);
        assert_eq!(
            evaluate_vaults(std::slice::from_ref(&p)),
            FindingStatus::Warning
        );
        let off = VaultPosture {
            soft_delete: "Disabled".into(),
            immutability: "Disabled".into(),
            ..p.clone()
        };
        assert_eq!(evaluate_vaults(&[off]), FindingStatus::Fail);
        let good = VaultPosture {
            immutability: "Locked".into(),
            ..p
        };
        assert_eq!(evaluate_vaults(&[good]), FindingStatus::Pass);
        assert_eq!(evaluate_vaults(&[]), FindingStatus::Info);
    }

    #[test]
    fn m365_backup_workloads() {
        let active = vec![json!({"status": "active"})];
        let inactive = vec![json!({"status": "inactive"})];
        let (on, off) = active_workloads(&active, &inactive, &[]);
        assert_eq!(on, vec!["Exchange"]);
        assert_eq!(off, vec!["SharePoint", "OneDrive"]);
        assert_eq!(evaluate_m365(on.len()), FindingStatus::Warning);
        assert_eq!(evaluate_m365(3), FindingStatus::Pass);
        assert_eq!(evaluate_m365(0), FindingStatus::Fail);
    }
}
