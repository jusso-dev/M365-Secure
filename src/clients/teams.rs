//! Teams admin configuration, read from the backend the Teams PowerShell module uses.
//!
//! `GET /beta/teamwork` carries none of the federation, meeting, app or messaging policy settings, so
//! the checks read `Skype.Policy/Configuration/<cmdlet noun>` instead. Each endpoint returns the same
//! fields as the matching `Get-Cs*` cmdlet. The API is undocumented: callers degrade to `Unknown` when
//! it refuses the app or changes shape.

use anyhow::Result;
use serde_json::Value;

use crate::auth::Resource;
use crate::graph::GraphClient;

const BASE: &str = "https://api.interfaces.records.teams.microsoft.com/Skype.Policy/Configuration";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamsConfig {
    TenantFederationSettings,
    TeamsClientConfiguration,
    TeamsMeetingPolicy,
    TeamsAppPermissionPolicy,
    TeamsAppSetupPolicy,
    TeamsMessagingPolicy,
}

impl TeamsConfig {
    pub fn name(&self) -> &'static str {
        match self {
            Self::TenantFederationSettings => "TenantFederationSettings",
            Self::TeamsClientConfiguration => "TeamsClientConfiguration",
            Self::TeamsMeetingPolicy => "TeamsMeetingPolicy",
            Self::TeamsAppPermissionPolicy => "TeamsAppPermissionPolicy",
            Self::TeamsAppSetupPolicy => "TeamsAppSetupPolicy",
            Self::TeamsMessagingPolicy => "TeamsMessagingPolicy",
        }
    }

    /// The cmdlet whose output this configuration mirrors, for messages.
    pub fn cmdlet(&self) -> String {
        format!("Get-Cs{}", self.name())
    }
}

/// Fetch a configuration and return its tenant-wide (`Global`) instance.
pub async fn get_global(graph: &GraphClient, cfg: TeamsConfig) -> Result<Value> {
    let url = format!("{}/{}", BASE, cfg.name());
    let body = graph.get_resource_json(Resource::TeamsAdmin, &url).await?;
    pick_global(&body, cfg)
}

/// The Global policy from a configuration response. Tolerates a bare array, `{value:[...]}` and a single
/// object. Per-user policies carry `Tag:` identities; the tenant default is `Global`.
pub fn pick_global(body: &Value, cfg: TeamsConfig) -> Result<Value> {
    let items: Vec<&Value> = match body {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => match body.get("value").and_then(|v| v.as_array()) {
            Some(a) => a.iter().collect(),
            None => vec![body],
        },
        _ => vec![],
    };
    let items: Vec<&Value> = items.into_iter().filter(|v| v.is_object()).collect();
    if items.is_empty() {
        anyhow::bail!(
            "{} returned no policies; the Teams admin API may have refused the app or changed shape",
            cfg.cmdlet()
        );
    }
    let global = items
        .iter()
        .find(|v| identity(v).is_some_and(|id| id.eq_ignore_ascii_case("Global")))
        .or_else(|| items.iter().find(|v| identity(v).is_none()))
        .or_else(|| items.first());
    global
        .map(|v| (*v).clone())
        .ok_or_else(|| anyhow::anyhow!("{} has no Global policy", cfg.cmdlet()))
}

fn identity(v: &Value) -> Option<&str> {
    v.get("Identity")
        .or_else(|| v.get("identity"))
        .and_then(|i| i.as_str())
        .map(|i| i.strip_prefix("Tag:").unwrap_or(i))
}

/// A boolean the API may send as JSON `true` or the string `"True"`.
pub fn bool_of(v: &Value, key: &str) -> Option<bool> {
    match v.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// An enum-valued setting as its string name.
pub fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|s| s.as_str())
}

/// `AllowedDomains` on the federation configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedDomains {
    /// `AllowAllKnownDomains`: every external tenant may federate.
    All,
    List(Vec<String>),
}

impl AllowedDomains {
    /// PowerShell shows `AllowAllKnownDomains` or `Domain=contoso.com`; the API nests these as objects. A
    /// missing value is the default, which is all domains.
    pub fn parse(federation: &Value) -> Self {
        let Some(v) = federation.get("AllowedDomains") else {
            return Self::All;
        };
        fn domains_from(v: &Value) -> Vec<String> {
            match v {
                Value::String(s) => s
                    .split([',', ';', ' '])
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())
                    .collect(),
                Value::Array(a) => a.iter().flat_map(domains_from).collect(),
                Value::Object(o) => o
                    .iter()
                    .flat_map(|(k, inner)| {
                        if k.eq_ignore_ascii_case("Domain")
                            || k.eq_ignore_ascii_case("AllowedDomain")
                            || k.eq_ignore_ascii_case("Domains")
                        {
                            domains_from(inner)
                        } else {
                            vec![]
                        }
                    })
                    .collect(),
                _ => vec![],
            }
        }
        match v {
            Value::Null => Self::All,
            Value::String(s) if s.eq_ignore_ascii_case("AllowAllKnownDomains") => Self::All,
            Value::Object(o)
                if o.keys()
                    .any(|k| k.eq_ignore_ascii_case("AllowAllKnownDomains")) =>
            {
                Self::All
            }
            other => {
                let list = domains_from(other);
                if list.is_empty() && !matches!(other, Value::Array(_)) {
                    Self::All
                } else {
                    Self::List(list)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn picks_global_from_array_and_value_wrapper() {
        let arr = json!([{"Identity": "Tag:Restricted", "AllowCloudRecording": true}, {"Identity": "Global", "AllowCloudRecording": false}]);
        let g = pick_global(&arr, TeamsConfig::TeamsMeetingPolicy).unwrap();
        assert_eq!(g["AllowCloudRecording"], json!(false));

        let wrapped = json!({"value": [{"Identity": "Global", "AllowEmailIntoChannel": "False"}]});
        let g = pick_global(&wrapped, TeamsConfig::TeamsClientConfiguration).unwrap();
        assert_eq!(bool_of(&g, "AllowEmailIntoChannel"), Some(false));

        let single = json!({"AllowFederatedUsers": true});
        let g = pick_global(&single, TeamsConfig::TenantFederationSettings).unwrap();
        assert_eq!(bool_of(&g, "AllowFederatedUsers"), Some(true));

        assert!(pick_global(&json!([]), TeamsConfig::TeamsAppSetupPolicy).is_err());
        assert!(pick_global(&json!({"error": "nope"}), TeamsConfig::TeamsAppSetupPolicy).is_ok());
    }

    #[test]
    fn allowed_domains_shapes() {
        assert_eq!(AllowedDomains::parse(&json!({})), AllowedDomains::All);
        assert_eq!(
            AllowedDomains::parse(&json!({"AllowedDomains": {"AllowAllKnownDomains": {}}})),
            AllowedDomains::All
        );
        assert_eq!(
            AllowedDomains::parse(
                &json!({"AllowedDomains": {"AllowedDomain": [{"Domain": "contoso.com"}, {"Domain": "fabrikam.com"}]}})
            ),
            AllowedDomains::List(vec!["contoso.com".into(), "fabrikam.com".into()])
        );
        assert_eq!(
            AllowedDomains::parse(&json!({"AllowedDomains": ["contoso.com"]})),
            AllowedDomains::List(vec!["contoso.com".into()])
        );
        assert_eq!(
            AllowedDomains::parse(&json!({"AllowedDomains": []})),
            AllowedDomains::List(vec![])
        );
    }
}
