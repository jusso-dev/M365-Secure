use anyhow::Result;
use chrono::Utc;

use super::{AuthConfig, TokenInfo, GRAPH_SCOPES};

pub async fn authenticate(
    config: &AuthConfig,
    client_id: &str,
    client_secret: &str,
) -> Result<TokenInfo> {
    let client = reqwest::Client::new();
    let token_url = format!(
        "{}/{}/oauth2/v2.0/token",
        config.cloud_environment.login_endpoint(),
        config.tenant_id,
    );

    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", config.cloud_environment.graph_scope()),
        ("grant_type", "client_credentials"),
    ];

    let resp = client.post(&token_url).form(&params).send().await?;

    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await?;
        anyhow::bail!(
            "Client credentials authentication failed: {}",
            body.get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error")
        );
    }

    let body: serde_json::Value = resp.json().await?;
    let access_token = body["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access token in response"))?;

    tracing::info!("Client credentials authentication successful");

    Ok(TokenInfo {
        access_token: access_token.to_string(),
        refresh_token: None, // Client credentials don't have refresh tokens
        expires_at: Utc::now()
            + chrono::Duration::seconds(body["expires_in"].as_i64().unwrap_or(3600)),
        tenant_id: config.tenant_id.clone(),
        scopes: GRAPH_SCOPES.iter().map(|s| s.to_string()).collect(),
    })
}
