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
];

#[derive(Clone)]
pub struct AuthManager {
    config: AuthConfig,
    token: Arc<RwLock<Option<TokenInfo>>>,
    exo_token: Arc<RwLock<Option<TokenInfo>>>,
    cache: token_cache::TokenCache,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        let cache = token_cache::TokenCache::new(&config.tenant_id);
        Self {
            config,
            token: Arc::new(RwLock::new(None)),
            exo_token: Arc::new(RwLock::new(None)),
            cache,
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

    /// Get an Exchange Online token (for outlook.office365.com admin API).
    /// Uses the refresh token from the Graph login to acquire a token scoped to EXO.
    pub async fn get_exo_token(&self) -> Result<String> {
        // Check if we already have a valid EXO token
        {
            let token = self.exo_token.read().await;
            if let Some(t) = &*token {
                if !t.is_expired() {
                    return Ok(t.access_token.clone());
                }
            }
        }

        // Acquire a new EXO token using the Graph refresh token
        let refresh = {
            let token = self.token.read().await;
            match &*token {
                Some(t) => t.refresh_token.clone(),
                None => None,
            }
        };

        if let Some(refresh_token) = refresh {
            let exo_token = self.acquire_exo_token(&refresh_token).await?;
            let access = exo_token.access_token.clone();
            let mut token = self.exo_token.write().await;
            *token = Some(exo_token);
            return Ok(access);
        }

        anyhow::bail!(
            "No refresh token available to acquire Exchange Online token. \
             Re-run `m365-assess auth login` with device code flow."
        )
    }

    async fn acquire_exo_token(&self, refresh_token: &str) -> Result<TokenInfo> {
        let client = reqwest::Client::new();
        let token_url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.config.cloud_environment.login_endpoint(),
            self.config.tenant_id
        );

        let exo_scope = match self.config.cloud_environment {
            CloudEnvironment::Commercial => "https://outlook.office365.com/.default",
            CloudEnvironment::GccHigh => "https://outlook.office365.us/.default",
            CloudEnvironment::Dod => "https://outlook.office365.us/.default",
        };

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", exo_scope),
        ];

        let resp = client.post(&token_url).form(&params).send().await?;

        let body: serde_json::Value = resp.json().await?;

        if let Some(error) = body.get("error") {
            let desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            anyhow::bail!("Exchange token acquisition failed: {} - {}", error, desc);
        }

        tracing::info!("Acquired Exchange Online token");

        Ok(TokenInfo {
            access_token: body["access_token"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("No access_token in EXO response"))?
                .to_string(),
            refresh_token: body
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(String::from),
            expires_at: Utc::now()
                + chrono::Duration::seconds(body["expires_in"].as_i64().unwrap_or(3600)),
            tenant_id: self.config.tenant_id.clone(),
            scopes: vec!["https://outlook.office365.com/.default".to_string()],
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
