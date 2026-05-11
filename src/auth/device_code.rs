use anyhow::Result;
use chrono::Utc;
use colored::Colorize;

use super::{AuthConfig, TokenInfo, GRAPH_SCOPES};

#[derive(serde::Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
    message: String,
}

pub async fn authenticate(config: &AuthConfig) -> Result<TokenInfo> {
    let client = reqwest::Client::new();
    let device_code_url = format!(
        "{}/{}/oauth2/v2.0/devicecode",
        config.cloud_environment.login_endpoint(),
        config.tenant_id,
    );

    let scopes = GRAPH_SCOPES.join(" ");
    let params = [("client_id", config.client_id.as_str()), ("scope", &scopes)];

    let resp = client.post(&device_code_url).form(&params).send().await?;

    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await?;
        anyhow::bail!(
            "Failed to initiate device code flow: {}",
            body.get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error")
        );
    }

    let dc: DeviceCodeResponse = resp.json().await?;

    println!();
    println!(
        "{}",
        "=== Microsoft 365 Authentication ===".bright_cyan().bold()
    );
    println!();
    println!("{}", dc.message);
    println!();
    println!("  Code: {}", dc.user_code.bright_yellow().bold());
    println!("  URL:  {}", dc.verification_uri.bright_blue().underline());
    println!();

    // Try to open browser automatically
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(&dc.verification_uri)
            .spawn();
    }

    // Poll for token
    let token_url = format!(
        "{}/{}/oauth2/v2.0/token",
        config.cloud_environment.login_endpoint(),
        config.tenant_id,
    );

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(dc.expires_in);
    let interval = std::time::Duration::from_secs(dc.interval.max(5));

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("Device code authentication timed out");
        }

        tokio::time::sleep(interval).await;

        let params = [
            ("client_id", config.client_id.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", dc.device_code.as_str()),
        ];

        let resp = client.post(&token_url).form(&params).send().await?;

        let body: serde_json::Value = resp.json().await?;

        if let Some(access_token) = body.get("access_token").and_then(|v| v.as_str()) {
            println!("{}", "Authentication successful!".bright_green().bold());
            return Ok(TokenInfo {
                access_token: access_token.to_string(),
                refresh_token: body
                    .get("refresh_token")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                expires_at: Utc::now()
                    + chrono::Duration::seconds(body["expires_in"].as_i64().unwrap_or(3600)),
                tenant_id: config.tenant_id.clone(),
                scopes: GRAPH_SCOPES.iter().map(|s| s.to_string()).collect(),
            });
        }

        if let Some(error) = body.get("error").and_then(|v| v.as_str()) {
            match error {
                "authorization_pending" => continue,
                "slow_down" => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                "authorization_declined" => {
                    anyhow::bail!("Authentication was declined by the user");
                }
                "expired_token" => {
                    anyhow::bail!("Device code expired. Please try again.");
                }
                _ => {
                    let desc = body
                        .get("error_description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");
                    anyhow::bail!("Authentication error: {} - {}", error, desc);
                }
            }
        }
    }
}
