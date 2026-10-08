pub mod client_credentials;
pub mod device_code;
pub mod token_cache;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

impl TokenInfo {
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at - chrono::Duration::minutes(5)
    }
}

#[derive(Debug, Clone)]
pub enum AuthMethod {
    DeviceCode,
    ClientCredentials {
        client_id: String,
        client_secret: String,
    },
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub method: AuthMethod,
    pub cloud_environment: CloudEnvironment,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CloudEnvironment {
    Commercial,
    GccHigh,
    Dod,
}

impl CloudEnvironment {
    pub fn login_endpoint(&self) -> &str {
        match self {
            CloudEnvironment::Commercial => "https://login.microsoftonline.com",
            CloudEnvironment::GccHigh => "https://login.microsoftonline.us",
            CloudEnvironment::Dod => "https://login.microsoftonline.us",
        }
    }

    pub fn graph_endpoint(&self) -> &str {
        match self {
            CloudEnvironment::Commercial => "https://graph.microsoft.com",
            CloudEnvironment::GccHigh => "https://graph.microsoft.us",
            CloudEnvironment::Dod => "https://dod-graph.microsoft.us",
        }
    }

    pub fn graph_scope(&self) -> &str {
        match self {
            CloudEnvironment::Commercial => "https://graph.microsoft.com/.default",
            CloudEnvironment::GccHigh => "https://graph.microsoft.us/.default",
            CloudEnvironment::Dod => "https://dod-graph.microsoft.us/.default",
        }
    }
}

impl std::fmt::Display for CloudEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudEnvironment::Commercial => write!(f, "Commercial"),
            CloudEnvironment::GccHigh => write!(f, "GCC High"),
            CloudEnvironment::Dod => write!(f, "DoD"),
        }
    }
}

/// Required Graph API permissions for full assessment
pub const GRAPH_SCOPES: &[&str] = &[
    "Organization.Read.All",
    "Domain.Read.All",
    "User.Read.All",
    "AuditLog.Read.All",
    "UserAuthenticationMethod.Read.All",
    "RoleManagement.Read.Directory",
    "Policy.Read.All",
    "Application.Read.All",
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementRBAC.Read.All",
    "DeviceManagementApps.Read.All",
    "SecurityEvents.Read.All",
    "SharePointTenantSettings.Read.All",
    "TeamSettings.Read.All",
    "TeamworkAppSettings.Read.All",
    "MailboxSettings.Read",
    "Team.ReadBasic.All",
    "TeamMember.Read.All",
    "Channel.ReadBasic.All",
    "Reports.Read.All",
    "Sites.Read.All",
    "SecurityAlert.Read.All",
    // Needed by the Purview, PIM, access review, enrolment and backup checks.
    "InformationProtectionPolicy.Read.All",
    "RecordsManagement.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "AccessReview.Read.All",
    "RoleManagementPolicy.Read.Directory",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleAssignmentSchedule.Read.Directory",
    "OnPremDirectorySynchronization.Read.All",
    "CrossTenantInformation.ReadBasic.All",
    "Policy.Read.ConditionalAccess",
    "IdentityRiskyUser.Read.All",
    "Group.Read.All",
    "SecurityIdentitiesSensors.Read.All",
    "SecurityIdentitiesHealth.Read.All",
    "BackupRestore-Configuration.Read.All",
    "AuditLogsQuery.Read.All",
    "ThreatHunting.Read.All",
    "CustomDetection.Read.All",
];

/// Resources other than Microsoft Graph that some checks read. Tokens for these are acquired with the
/// Graph refresh token, so the signed-in app must be consented for the resource (device-code sign-in with
/// a first-party app covers Exchange; Azure, SharePoint admin, Teams and Defender for Endpoint usually
/// need a tenant-owned app registration, see README "Beyond Graph").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    Graph,
    ExchangeOnline,
    AzureResourceManager,
    SharePointAdmin,
    TeamsAdmin,
    DefenderForEndpoint,
    PowerPlatform,
}

impl Resource {
    pub fn display_name(&self) -> &'static str {
        match self {
            Resource::Graph => "Microsoft Graph",
            Resource::ExchangeOnline => "Exchange Online admin API",
            Resource::AzureResourceManager => "Azure Resource Manager",
            Resource::SharePointAdmin => "SharePoint Online admin",
            Resource::TeamsAdmin => "Teams admin (Skype.Policy)",
            Resource::DefenderForEndpoint => "Defender for Endpoint API",
            Resource::PowerPlatform => "Power Platform API",
        }
    }
}

#[derive(Clone)]
pub struct AuthManager {
    config: AuthConfig,
    token: Arc<RwLock<Option<TokenInfo>>>,
    /// Tokens for non-Graph resources, keyed by the scope string they were issued for.
    resource_tokens: Arc<RwLock<std::collections::HashMap<String, TokenInfo>>>,
    cache: token_cache::TokenCache,
    /// SharePoint tenant name (the part before `.sharepoint.com`), learned from the default domain at scan time.
    sharepoint_tenant: Arc<RwLock<Option<String>>>,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        let cache = token_cache::TokenCache::new(&config.tenant_id);
        Self {
            config,
            token: Arc::new(RwLock::new(None)),
            resource_tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
            cache,
            sharepoint_tenant: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn login(&self) -> Result<()> {
        // Try loading from cache first
        if let Ok(Some(cached)) = self.cache.load() {
            if !cached.is_expired() {
                tracing::info!("Using cached token for tenant {}", self.config.tenant_id);
                let mut token = self.token.write().await;
                *token = Some(cached);
                return Ok(());
            }
            // Try refresh
            if let Some(ref refresh) = cached.refresh_token {
                tracing::info!("Refreshing expired token");
                if let Ok(refreshed) = self.refresh_token(refresh).await {
                    self.cache.save(&refreshed)?;
                    let mut token = self.token.write().await;
                    *token = Some(refreshed);
                    return Ok(());
                }
            }
        }

        // Perform fresh login
        let token_info = match &self.config.method {
            AuthMethod::DeviceCode => device_code::authenticate(&self.config).await?,
            AuthMethod::ClientCredentials {
                client_id,
                client_secret,
            } => client_credentials::authenticate(&self.config, client_id, client_secret).await?,
        };

        self.cache.save(&token_info)?;
        let mut token = self.token.write().await;
        *token = Some(token_info);
        Ok(())
    }

    pub async fn get_token(&self) -> Result<String> {
        // First check if we have a valid token
        {
            let token = self.token.read().await;
            if let Some(t) = &*token {
                if !t.is_expired() {
                    return Ok(t.access_token.clone());
                }
            }
        }
        // Token is expired or missing - try refresh
        let refresh_token = {
            let token = self.token.read().await;
            match &*token {
                Some(t) => t.refresh_token.clone(),
                None => None,
            }
        };
        if let Some(refresh) = refresh_token {
            if let Ok(refreshed) = self.refresh_token(&refresh).await {
                self.cache.save(&refreshed)?;
                let access = refreshed.access_token.clone();
                let mut token = self.token.write().await;
                *token = Some(refreshed);
                return Ok(access);
            }
        }
        // Check if we have any token at all
        let token = self.token.read().await;
        match &*token {
            Some(_) => anyhow::bail!(
                "Token expired and refresh failed. Run `m365-assess auth login` again."
            ),
            None => anyhow::bail!("Not authenticated. Run `m365-assess auth login` first."),
        }
    }

    pub async fn logout(&self) -> Result<()> {
        self.cache.clear()?;
        let mut token = self.token.write().await;
        *token = None;
        Ok(())
    }

    /// Record the SharePoint tenant name (e.g. `contoso` for contoso.sharepoint.com) so SharePoint admin
    /// tokens can be requested. Called by the engine once tenant information is known.
    pub async fn set_sharepoint_tenant(&self, tenant: &str) {
        let mut t = self.sharepoint_tenant.write().await;
        *t = Some(tenant.to_string());
    }

    /// The OAuth scope used to request a token for a resource in the configured cloud.
    pub async fn scope_for(&self, resource: Resource) -> Result<String> {
        let commercial = self.config.cloud_environment == CloudEnvironment::Commercial;
        Ok(match resource {
            Resource::Graph => self.config.cloud_environment.graph_scope().to_string(),
            Resource::ExchangeOnline => if commercial {
                "https://outlook.office365.com/.default"
            } else {
                "https://outlook.office365.us/.default"
            }
            .to_string(),
            Resource::AzureResourceManager => if commercial {
                "https://management.azure.com/.default"
            } else {
                "https://management.usgovcloudapi.net/.default"
            }
            .to_string(),
            Resource::SharePointAdmin => {
                let tenant = self.sharepoint_tenant.read().await.clone().ok_or_else(|| {
                    anyhow::anyhow!("SharePoint tenant name not known yet; tenant information must be collected first")
                })?;
                let suffix = if commercial {
                    "sharepoint.com"
                } else {
                    "sharepoint.us"
                };
                format!("https://{}-admin.{}/.default", tenant, suffix)
            }
            // The Teams admin backend used by the Teams PowerShell module. Undocumented, so checks that use it
            // must degrade to Unknown when it refuses the app.
            Resource::TeamsAdmin => "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default".to_string(),
            Resource::DefenderForEndpoint => if commercial {
                "https://api.securitycenter.microsoft.com/.default"
            } else {
                "https://api-gcc.securitycenter.microsoft.us/.default"
            }
            .to_string(),
            Resource::PowerPlatform => "https://api.powerplatform.com/.default".to_string(),
        })
    }

    /// Get an access token for a non-Graph resource, exchanging the Graph refresh token for it.
    /// Errors name the resource and, for consent failures, say what to do.
    pub async fn get_resource_token(&self, resource: Resource) -> Result<String> {
        Ok(self.get_resource_token_info(resource).await?.access_token)
    }

    /// Like [`get_resource_token`](Self::get_resource_token) but with expiry and scope, for callers that
    /// hand the token to another runtime (the Junction gateway).
    pub async fn get_resource_token_info(&self, resource: Resource) -> Result<TokenInfo> {
        if resource == Resource::Graph {
            self.get_token().await?;
            let token = self.token.read().await;
            return token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Not authenticated"));
        }
        let scope = self.scope_for(resource).await?;
        {
            let tokens = self.resource_tokens.read().await;
            if let Some(t) = tokens.get(&scope) {
                if !t.is_expired() {
                    return Ok(t.clone());
                }
            }
        }
        let refresh = {
            let token = self.token.read().await;
            token.as_ref().and_then(|t| t.refresh_token.clone())
        };
        let Some(refresh_token) = refresh else {
            anyhow::bail!(
                "No refresh token available to acquire a {} token. Sign in with the device code flow,                  or use client credentials with an app consented for this resource.",
                resource.display_name()
            )
        };
        let token = self
            .acquire_resource_token(&refresh_token, &scope, resource)
            .await?;
        self.resource_tokens
            .write()
            .await
            .insert(scope, token.clone());
        Ok(token)
    }

    pub fn tenant_id(&self) -> &str {
        &self.config.tenant_id
    }

    /// Kept for existing callers; prefer `get_resource_token(Resource::ExchangeOnline)`.
    pub async fn get_exo_token(&self) -> Result<String> {
        self.get_resource_token(Resource::ExchangeOnline).await
    }

    async fn acquire_resource_token(
        &self,
        refresh_token: &str,
        scope: &str,
        resource: Resource,
    ) -> Result<TokenInfo> {
        let client = reqwest::Client::new();
        let token_url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.config.cloud_environment.login_endpoint(),
            self.config.tenant_id
        );
        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", scope),
        ];
        let resp = client.post(&token_url).form(&params).send().await?;
        let body: serde_json::Value = resp.json().await?;

        if let Some(error) = body.get("error") {
            let desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            let hint = if desc.contains("AADSTS65001")
                || desc.contains("AADSTS650057")
                || desc.contains("AADSTS70011")
            {
                format!(
                    " The signed-in app isn't consented for {}. Register an app with that API permission and pass                      --client-id, or skip the module.",
                    resource.display_name()
                )
            } else {
                String::new()
            };
            anyhow::bail!(
                "{} token acquisition failed: {} - {}{}",
                resource.display_name(),
                error,
                desc,
                hint
            );
        }

        tracing::info!("Acquired {} token", resource.display_name());
        Ok(TokenInfo {
            access_token: body["access_token"]
                .as_str()
                .ok_or_else(|| {
                    anyhow::anyhow!("No access_token in {} response", resource.display_name())
                })?
                .to_string(),
            refresh_token: body
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(String::from),
            expires_at: Utc::now()
                + chrono::Duration::seconds(body["expires_in"].as_i64().unwrap_or(3600)),
            tenant_id: self.config.tenant_id.clone(),
            scopes: vec![scope.to_string()],
        })
    }

    pub fn cloud(&self) -> CloudEnvironment {
        self.config.cloud_environment
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenInfo> {
        let client = reqwest::Client::new();
        let token_url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.config.cloud_environment.login_endpoint(),
            self.config.tenant_id
        );

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", self.config.cloud_environment.graph_scope()),
        ];

        let resp = client.post(&token_url).form(&params).send().await?;

        let body: serde_json::Value = resp.json().await?;

        if let Some(error) = body.get("error") {
            anyhow::bail!("Token refresh failed: {}", error);
        }

        Ok(TokenInfo {
            access_token: body["access_token"].as_str().unwrap().to_string(),
            refresh_token: body
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(String::from),
            expires_at: Utc::now()
                + chrono::Duration::seconds(body["expires_in"].as_i64().unwrap_or(3600)),
            tenant_id: self.config.tenant_id.clone(),
            scopes: GRAPH_SCOPES.iter().map(|s| s.to_string()).collect(),
        })
    }
}
