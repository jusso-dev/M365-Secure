//! SharePoint Online tenant administration.
//!
//! Graph `admin/sharepoint/settings` omits the default link type and permission, Anyone-link expiry,
//! OneDrive sharing and most of what `Get-SPOTenant` returns. Those live on the CSOM `Tenant` object, read
//! here with the same `ProcessQuery` request PnP and the SPO management shell send. Graph fills the gaps
//! CSOM does not carry (idle session sign-out, Mac sync app), and stands in when the admin token is refused.

use anyhow::{Context, Result};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;

use crate::auth::Resource;
use crate::graph::GraphClient;

/// CSOM type id of `Microsoft.Online.SharePoint.TenantAdministration.Tenant`.
const TENANT_TYPE_ID: &str = "{268004ae-ef6b-4e9b-8425-127220d84719}";

fn process_query_body() -> String {
    format!(
        concat!(
            r#"<Request AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" "#,
            r#"ApplicationName="m365-assess" xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">"#,
            r#"<Actions><ObjectPath Id="2" ObjectPathId="1"/><Query Id="3" ObjectPathId="1">"#,
            r#"<Query SelectAllProperties="true"><Properties/></Query></Query></Actions>"#,
            r#"<ObjectPaths><Constructor Id="1" TypeId="{}"/></ObjectPaths></Request>"#
        ),
        TENANT_TYPE_ID
    )
}

/// Read every property of the tenant admin object. Errors name the resource; a consent failure carries
/// the hint from `AuthManager::get_resource_token`, which callers surface as `Unknown`.
pub async fn fetch_tenant_properties(graph: &GraphClient) -> Result<Value> {
    let auth = graph.auth();
    let scope = auth.scope_for(Resource::SharePointAdmin).await?;
    let admin_url = scope.trim_end_matches("/.default").to_string();
    let token = auth.get_resource_token(Resource::SharePointAdmin).await?;
    let url = format!("{}/_vti_bin/client.svc/ProcessQuery", admin_url);

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let resp = http
        .post(&url)
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .header(CONTENT_TYPE, "text/xml")
        .header(ACCEPT, "application/json")
        .body(process_query_body())
        .send()
        .await
        .with_context(|| format!("SharePoint Online admin request to {url} failed"))?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "SharePoint Online admin returned {} for {}: {}",
            status,
            url,
            text.chars().take(300).collect::<String>()
        );
    }
    let body: Value = serde_json::from_str(&text)
        .with_context(|| "SharePoint Online admin ProcessQuery response was not JSON")?;
    parse_process_query(&body)
}

/// Pull the tenant object out of a `ProcessQuery` response. The response is an array whose first element
/// carries `ErrorInfo`; the object with `_ObjectType_` ending in `.Tenant` holds the properties.
pub fn parse_process_query(body: &Value) -> Result<Value> {
    let items = body
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("ProcessQuery response is not an array"))?;
    if let Some(err) = items
        .first()
        .and_then(|h| h.get("ErrorInfo"))
        .filter(|e| !e.is_null())
    {
        let msg = err
            .get("ErrorMessage")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        let code = err
            .get("ErrorTypeName")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        anyhow::bail!("SharePoint Online admin ProcessQuery error {code}: {msg}");
    }
    items
        .iter()
        .rev()
        .find(|v| {
            v.get("_ObjectType_")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t.ends_with(".Tenant"))
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("ProcessQuery response had no Tenant object"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingCapability {
    Disabled,
    ExternalUserSharingOnly,
    ExternalUserAndGuestSharing,
    ExistingExternalUserSharingOnly,
}

impl SharingCapability {
    /// CSOM serialises the enum as its integer; Graph uses camelCase names.
    pub fn parse(v: &Value) -> Option<Self> {
        match v {
            Value::Number(n) => match n.as_i64()? {
                0 => Some(Self::Disabled),
                1 => Some(Self::ExternalUserSharingOnly),
                2 => Some(Self::ExternalUserAndGuestSharing),
                3 => Some(Self::ExistingExternalUserSharingOnly),
                _ => None,
            },
            Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "disabled" => Some(Self::Disabled),
                "externalusersharingonly" => Some(Self::ExternalUserSharingOnly),
                "externaluserandguestsharing" => Some(Self::ExternalUserAndGuestSharing),
                "existingexternalusersharingonly" => Some(Self::ExistingExternalUserSharingOnly),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Disabled => "Only people in your organization",
            Self::ExternalUserSharingOnly => "New and existing guests",
            Self::ExternalUserAndGuestSharing => "Anyone",
            Self::ExistingExternalUserSharingOnly => "Existing guests",
        }
    }

    pub fn allows_anyone_links(&self) -> bool {
        *self == Self::ExternalUserAndGuestSharing
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    None,
    Direct,
    Internal,
    AnonymousAccess,
}

impl LinkType {
    pub fn parse(v: &Value) -> Option<Self> {
        match v {
            Value::Number(n) => match n.as_i64()? {
                0 => Some(Self::None),
                1 => Some(Self::Direct),
                2 => Some(Self::Internal),
                3 => Some(Self::AnonymousAccess),
                _ => None,
            },
            Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "none" => Some(Self::None),
                "direct" | "specificpeople" => Some(Self::Direct),
                "internal" => Some(Self::Internal),
                "anonymousaccess" | "anyone" => Some(Self::AnonymousAccess),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "Not set",
            Self::Direct => "Specific people",
            Self::Internal => "People in your organization",
            Self::AnonymousAccess => "Anyone",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPermission {
    None,
    View,
    Edit,
}

impl LinkPermission {
    pub fn parse(v: &Value) -> Option<Self> {
        match v {
            Value::Number(n) => match n.as_i64()? {
                0 => Some(Self::None),
                1 => Some(Self::View),
                2 => Some(Self::Edit),
                _ => None,
            },
            Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "none" => Some(Self::None),
                "view" => Some(Self::View),
                "edit" => Some(Self::Edit),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "Not set",
            Self::View => "View",
            Self::Edit => "Edit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainRestrictionMode {
    None,
    AllowList,
    BlockList,
}

impl DomainRestrictionMode {
    pub fn parse(v: &Value) -> Option<Self> {
        match v {
            Value::Number(n) => match n.as_i64()? {
                0 => Some(Self::None),
                1 => Some(Self::AllowList),
                2 => Some(Self::BlockList),
                _ => None,
            },
            Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "none" => Some(Self::None),
                "allowlist" => Some(Self::AllowList),
                "blocklist" => Some(Self::BlockList),
                _ => None,
            },
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleSessionSignOut {
    pub is_enabled: bool,
    pub sign_out_after_seconds: i64,
}

/// Tenant sharing posture normalised from CSOM (`Get-SPOTenant` names) and Graph `sharepointSettings`.
/// Every field is `Option`: `None` means neither source returned it, and checks that need it report
/// `Unknown` with the reason rather than guessing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TenantSharing {
    pub sharing_capability: Option<SharingCapability>,
    pub onedrive_sharing_capability: Option<SharingCapability>,
    pub default_link_type: Option<LinkType>,
    pub default_link_permission: Option<LinkPermission>,
    /// `RequireAnonymousLinksExpireInDays`; 0 or negative means Anyone links never expire.
    pub anonymous_link_expire_in_days: Option<i64>,
    pub file_anonymous_link_type: Option<LinkPermission>,
    pub folder_anonymous_link_type: Option<LinkPermission>,
    pub domain_restriction_mode: Option<DomainRestrictionMode>,
    pub allowed_domains: Vec<String>,
    pub prevent_external_resharing: Option<bool>,
    pub external_user_expiration_required: Option<bool>,
    pub external_user_expire_in_days: Option<i64>,
    pub email_attestation_required: Option<bool>,
    pub email_attestation_reauth_days: Option<i64>,
    pub legacy_auth_protocols_enabled: Option<bool>,
    pub restricted_access_control_enabled: Option<bool>,
    /// `WhoCanShareAllowListInTenant`: security groups whose members may share externally.
    pub who_can_share_allow_list: Option<Vec<String>>,
    pub b2b_integration_enabled: Option<bool>,
    pub unmanaged_sync_restricted: Option<bool>,
    pub disallow_infected_file_download: Option<bool>,
    /// `DelayDenyAddAndCustomizePagesEnforcement`: true keeps custom script allowed past the platform default.
    pub delay_custom_script_enforcement: Option<bool>,
    pub loop_enabled: Option<bool>,
    pub onedrive_loop_sharing_capability: Option<SharingCapability>,
    pub idle_session_signout: Option<IdleSessionSignOut>,
    pub mac_sync_app_enabled: Option<bool>,
}

fn get_bool(v: &Value, key: &str) -> Option<bool> {
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

fn get_i64(v: &Value, key: &str) -> Option<i64> {
    match v.get(key)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn split_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => s
            .split([' ', ';', ','])
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|d| d.as_str())
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

impl TenantSharing {
    /// From the CSOM tenant object (PascalCase `Get-SPOTenant` property names).
    pub fn from_csom(t: &Value) -> Self {
        Self {
            sharing_capability: t
                .get("SharingCapability")
                .and_then(SharingCapability::parse),
            onedrive_sharing_capability: t
                .get("OneDriveSharingCapability")
                .and_then(SharingCapability::parse),
            default_link_type: t.get("DefaultSharingLinkType").and_then(LinkType::parse),
            default_link_permission: t
                .get("DefaultLinkPermission")
                .and_then(LinkPermission::parse),
            anonymous_link_expire_in_days: get_i64(t, "RequireAnonymousLinksExpireInDays"),
            file_anonymous_link_type: t
                .get("FileAnonymousLinkType")
                .and_then(LinkPermission::parse),
            folder_anonymous_link_type: t
                .get("FolderAnonymousLinkType")
                .and_then(LinkPermission::parse),
            domain_restriction_mode: t
                .get("SharingDomainRestrictionMode")
                .and_then(DomainRestrictionMode::parse),
            allowed_domains: split_list(t.get("SharingAllowedDomainList")),
            prevent_external_resharing: get_bool(t, "PreventExternalUsersFromResharing"),
            external_user_expiration_required: get_bool(t, "ExternalUserExpirationRequired"),
            external_user_expire_in_days: get_i64(t, "ExternalUserExpireInDays"),
            email_attestation_required: get_bool(t, "EmailAttestationRequired"),
            email_attestation_reauth_days: get_i64(t, "EmailAttestationReAuthDays"),
            legacy_auth_protocols_enabled: get_bool(t, "LegacyAuthProtocolsEnabled"),
            restricted_access_control_enabled: get_bool(t, "EnableRestrictedAccessControl"),
            who_can_share_allow_list: t
                .get("WhoCanShareAllowListInTenant")
                .filter(|v| !v.is_null())
                .map(|v| split_list(Some(v))),
            b2b_integration_enabled: get_bool(t, "EnableAzureADB2BIntegration"),
            unmanaged_sync_restricted: get_bool(t, "IsUnmanagedSyncClientForTenantRestricted"),
            disallow_infected_file_download: get_bool(t, "DisallowInfectedFileDownload"),
            delay_custom_script_enforcement: get_bool(
                t,
                "DelayDenyAddAndCustomizePagesEnforcement",
            ),
            loop_enabled: get_bool(t, "IsLoopEnabled"),
            onedrive_loop_sharing_capability: t
                .get("OneDriveLoopSharingCapability")
                .and_then(SharingCapability::parse),
            idle_session_signout: None,
            mac_sync_app_enabled: None,
        }
    }

    /// From Graph `GET /v1.0/admin/sharepoint/settings` (camelCase, a subset of the tenant properties).
    pub fn from_graph(s: &Value) -> Self {
        let idle = s.get("idleSessionSignOut").and_then(|i| {
            Some(IdleSessionSignOut {
                is_enabled: get_bool(i, "isEnabled")?,
                sign_out_after_seconds: get_i64(i, "signOutAfterInSeconds").unwrap_or(0),
            })
        });
        Self {
            sharing_capability: s
                .get("sharingCapability")
                .and_then(SharingCapability::parse),
            domain_restriction_mode: s
                .get("sharingDomainRestrictionMode")
                .and_then(DomainRestrictionMode::parse),
            allowed_domains: split_list(s.get("sharingAllowedDomainList")),
            prevent_external_resharing: get_bool(s, "isResharingByExternalUsersEnabled")
                .map(|b| !b),
            legacy_auth_protocols_enabled: get_bool(s, "isLegacyAuthProtocolsEnabled"),
            unmanaged_sync_restricted: get_bool(s, "isUnmanagedSyncAppForTenantRestricted"),
            loop_enabled: get_bool(s, "isLoopEnabled"),
            idle_session_signout: idle,
            mac_sync_app_enabled: get_bool(s, "isMacSyncAppEnabled"),
            ..Default::default()
        }
    }

    /// CSOM values win; Graph fills whatever CSOM did not return.
    pub fn merged(csom: Option<&Value>, graph: Option<&Value>) -> Self {
        let mut out = csom.map(Self::from_csom).unwrap_or_default();
        if let Some(g) = graph.map(Self::from_graph) {
            macro_rules! fill {
                ($($f:ident),*) => { $( if out.$f.is_none() { out.$f = g.$f; } )* };
            }
            fill!(
                sharing_capability,
                domain_restriction_mode,
                prevent_external_resharing,
                legacy_auth_protocols_enabled,
                unmanaged_sync_restricted,
                loop_enabled,
                idle_session_signout,
                mac_sync_app_enabled
            );
            if out.allowed_domains.is_empty() {
                out.allowed_domains = g.allowed_domains;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn csom_response() -> Value {
        json!([
            {"SchemaVersion":"15.0.0.0","LibraryVersion":"16.0.0.0","ErrorInfo":null,"TraceCorrelationId":"x"},
            2, {"IsNull": false},
            3, {
                "_ObjectType_": "Microsoft.Online.SharePoint.TenantAdministration.Tenant",
                "SharingCapability": 2,
                "OneDriveSharingCapability": 1,
                "DefaultSharingLinkType": 3,
                "DefaultLinkPermission": 2,
                "RequireAnonymousLinksExpireInDays": -1,
                "FileAnonymousLinkType": 2,
                "FolderAnonymousLinkType": 1,
                "SharingDomainRestrictionMode": 1,
                "SharingAllowedDomainList": "contoso.com fabrikam.com",
                "PreventExternalUsersFromResharing": false,
                "ExternalUserExpirationRequired": true,
                "ExternalUserExpireInDays": 60,
                "EmailAttestationRequired": true,
                "EmailAttestationReAuthDays": 15,
                "LegacyAuthProtocolsEnabled": false,
                "EnableRestrictedAccessControl": true,
                "WhoCanShareAllowListInTenant": "",
                "EnableAzureADB2BIntegration": true,
                "IsUnmanagedSyncClientForTenantRestricted": false,
                "DisallowInfectedFileDownload": true,
                "DelayDenyAddAndCustomizePagesEnforcement": false,
                "IsLoopEnabled": true,
                "OneDriveLoopSharingCapability": 2
            }
        ])
    }

    #[test]
    fn parses_tenant_object_from_process_query() {
        let tenant = parse_process_query(&csom_response()).unwrap();
        let s = TenantSharing::from_csom(&tenant);
        assert_eq!(
            s.sharing_capability,
            Some(SharingCapability::ExternalUserAndGuestSharing)
        );
        assert_eq!(
            s.onedrive_sharing_capability,
            Some(SharingCapability::ExternalUserSharingOnly)
        );
        assert_eq!(s.default_link_type, Some(LinkType::AnonymousAccess));
        assert_eq!(s.default_link_permission, Some(LinkPermission::Edit));
        assert_eq!(s.anonymous_link_expire_in_days, Some(-1));
        assert_eq!(s.file_anonymous_link_type, Some(LinkPermission::Edit));
        assert_eq!(
            s.domain_restriction_mode,
            Some(DomainRestrictionMode::AllowList)
        );
        assert_eq!(s.allowed_domains, vec!["contoso.com", "fabrikam.com"]);
        assert_eq!(s.prevent_external_resharing, Some(false));
        assert_eq!(s.external_user_expire_in_days, Some(60));
        assert_eq!(s.who_can_share_allow_list, Some(vec![]));
        assert_eq!(s.restricted_access_control_enabled, Some(true));
        assert_eq!(
            s.onedrive_loop_sharing_capability,
            Some(SharingCapability::ExternalUserAndGuestSharing)
        );
        assert_eq!(s.idle_session_signout, None);
    }

    #[test]
    fn process_query_error_is_surfaced() {
        let body = json!([{"ErrorInfo": {"ErrorMessage": "Access denied.", "ErrorTypeName": "System.UnauthorizedAccessException"}}]);
        let err = parse_process_query(&body).unwrap_err().to_string();
        assert!(err.contains("Access denied"), "{err}");
    }

    #[test]
    fn graph_fills_what_csom_lacks() {
        let graph = json!({
            "sharingCapability": "externalUserSharingOnly",
            "isResharingByExternalUsersEnabled": true,
            "isLegacyAuthProtocolsEnabled": true,
            "idleSessionSignOut": {"isEnabled": true, "signOutAfterInSeconds": 10800},
            "isMacSyncAppEnabled": false
        });
        let tenant = parse_process_query(&csom_response()).unwrap();
        let merged = TenantSharing::merged(Some(&tenant), Some(&graph));
        // CSOM wins where both answer.
        assert_eq!(
            merged.sharing_capability,
            Some(SharingCapability::ExternalUserAndGuestSharing)
        );
        assert_eq!(merged.legacy_auth_protocols_enabled, Some(false));
        // Graph fills the rest.
        assert_eq!(
            merged.idle_session_signout,
            Some(IdleSessionSignOut {
                is_enabled: true,
                sign_out_after_seconds: 10800
            })
        );
        assert_eq!(merged.mac_sync_app_enabled, Some(false));

        let graph_only = TenantSharing::merged(None, Some(&graph));
        assert_eq!(
            graph_only.sharing_capability,
            Some(SharingCapability::ExternalUserSharingOnly)
        );
        assert_eq!(graph_only.prevent_external_resharing, Some(false));
        assert_eq!(graph_only.default_link_type, None);
    }
}
