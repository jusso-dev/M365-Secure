//! Exchange Online cmdlet access shared by the Exchange, Security and Purview modules.
//!
//! Every setting here comes from `GraphClient::exo_invoke_cmdlet`, which runs an Exchange Online
//! cmdlet through the admin REST API. When a cmdlet is not reachable that way the error is
//! surfaced so the caller records `Unknown`; nothing in this module guesses a status.

use anyhow::Result;
use serde_json::Value;

use crate::assessment::finding::{Finding, FindingBuilder};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

/// A tenant-bound handle for running Exchange Online cmdlets.
pub struct Exo<'a> {
    graph: &'a GraphClient,
    tenant_id: &'a str,
}

impl<'a> Exo<'a> {
    pub fn new(graph: &'a GraphClient, tenant_id: &'a str) -> Self {
        Self { graph, tenant_id }
    }

    /// Run a cmdlet and return its result rows. A single-object response becomes one row.
    pub async fn get(&self, cmdlet: &str, params: Option<Value>) -> Result<Vec<Value>> {
        let body = self
            .graph
            .exo_invoke_cmdlet(self.tenant_id, cmdlet, params.as_ref())
            .await?;
        Ok(rows(body))
    }

    /// Run a cmdlet that returns exactly one object (`Get-OrganizationConfig`, `Get-TransportConfig`).
    pub async fn one(&self, cmdlet: &str) -> Result<Value> {
        self.get(cmdlet, None)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("{cmdlet} returned no data"))
    }

    /// Run a Security & Compliance PowerShell cmdlet. These are not served by the Exchange admin
    /// REST API, so the usual outcome is an error that names the manual path. Kept as a real call
    /// so a tenant where it does work is assessed instead of assumed.
    pub async fn get_sc(&self, cmdlet: &str, params: Option<Value>) -> Result<Vec<Value>> {
        self.get(cmdlet, params).await.map_err(|e| {
            anyhow::anyhow!(
                "{cmdlet} is a Security & Compliance PowerShell cmdlet and is not reachable through the \
                 Exchange admin REST API; attest this control in crownguard. ({e})"
            )
        })
    }
}

/// A cmdlet result kept for several checks; the error is a string so it can be reported more than once.
pub type Fetched = Result<Vec<Value>, String>;

impl Exo<'_> {
    /// [`Exo::get`] with the error flattened for sharing between checks.
    pub async fn fetch(&self, cmdlet: &str, params: Option<Value>) -> Fetched {
        self.get(cmdlet, params).await.map_err(|e| e.to_string())
    }
}

/// Borrow a shared result, turning its stored error back into one the caller can return.
pub fn need(fetched: &Fetched) -> Result<&[Value]> {
    fetched.as_deref().map_err(|e| anyhow::anyhow!("{e}"))
}

/// Normalise an admin API response into rows: `{"value":[...]}`, a bare array, or one object.
pub fn rows(body: Value) -> Vec<Value> {
    match body {
        Value::Array(a) => a,
        Value::Object(mut o) => match o.remove("value") {
            Some(Value::Array(a)) => a,
            Some(other) if !other.is_null() => vec![other],
            _ => {
                o.retain(|k, _| !k.starts_with("@odata"));
                if o.is_empty() {
                    vec![]
                } else {
                    vec![Value::Object(o)]
                }
            }
        },
        _ => vec![],
    }
}

/// Boolean property; `None` when the property is absent or not a bool.
pub fn bool_of(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

/// Boolean property, treating absence as `default`.
pub fn bool_or(v: &Value, key: &str, default: bool) -> bool {
    bool_of(v, key).unwrap_or(default)
}

pub fn str_of<'v>(v: &'v Value, key: &str) -> Option<&'v str> {
    v.get(key).and_then(Value::as_str)
}

pub fn i64_of(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(|x| {
        x.as_i64()
            .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
    })
}

/// String list property. The admin API returns arrays, single strings, or null for multi-valued
/// properties; all three are handled.
pub fn strs_of(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| {
                x.as_str().map(String::from).or_else(|| {
                    ["Name", "Domain", "Address", "Identity"]
                        .iter()
                        .find_map(|k| x.get(k).and_then(Value::as_str).map(String::from))
                })
            })
            .collect(),
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => vec![],
    }
}

/// Display name of a policy or rule row.
pub fn name_of(v: &Value) -> String {
    str_of(v, "Name")
        .or_else(|| str_of(v, "Identity"))
        .or_else(|| str_of(v, "DisplayName"))
        .unwrap_or("(unnamed)")
        .to_string()
}

/// `State` of a rule row is `Enabled`.
pub fn rule_enabled(v: &Value) -> bool {
    str_of(v, "State").is_none_or(|s| s.eq_ignore_ascii_case("Enabled"))
}

/// Join up to `cap` items, noting how many more there are.
pub fn list_preview(items: &[String], cap: usize) -> String {
    if items.len() <= cap {
        items.join(", ")
    } else {
        format!("{} and {} more", items[..cap].join(", "), items.len() - cap)
    }
}

/// Start a finding with the registry severity applied.
pub fn finding(
    registry: &ControlRegistry,
    check_id: &str,
    category: &str,
    section: &str,
    setting: &str,
    description: &str,
) -> FindingBuilder {
    Finding::new(check_id, category, section, setting, description)
        .severity(registry.get_severity(check_id))
}

/// Defender for Office 365 (Plan 1 or 2) is licensed.
pub fn has_mdo(tenant: &crate::assessment::engine::TenantInfo) -> bool {
    tenant.has_service_plan("ATP_ENTERPRISE") || tenant.has_service_plan("THREAT_INTELLIGENCE")
}

/// Defender for Office 365 Plan 2 is licensed.
pub fn has_mdo_p2(tenant: &crate::assessment::engine::TenantInfo) -> bool {
    tenant.has_service_plan("THREAT_INTELLIGENCE")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rows_unwraps_value_arrays_and_single_objects() {
        assert_eq!(rows(json!({"value": [{"a": 1}, {"a": 2}]})).len(), 2);
        assert_eq!(
            rows(json!({"@odata.context": "x", "AuditDisabled": false})).len(),
            1
        );
        assert_eq!(rows(json!([{"a": 1}])).len(), 1);
        assert!(rows(json!({"@odata.context": "x", "value": []})).is_empty());
        assert!(rows(Value::Null).is_empty());
    }

    #[test]
    fn strs_of_handles_scalar_and_array() {
        let v = json!({"A": ["x", "y"], "B": "z", "C": null, "D": [{"Name": "n"}]});
        assert_eq!(strs_of(&v, "A"), vec!["x", "y"]);
        assert_eq!(strs_of(&v, "B"), vec!["z"]);
        assert!(strs_of(&v, "C").is_empty());
        assert_eq!(strs_of(&v, "D"), vec!["n"]);
    }

    #[test]
    fn i64_of_parses_numeric_strings() {
        let v = json!({"A": 5, "B": "7", "C": "x"});
        assert_eq!(i64_of(&v, "A"), Some(5));
        assert_eq!(i64_of(&v, "B"), Some(7));
        assert_eq!(i64_of(&v, "C"), None);
    }
}
