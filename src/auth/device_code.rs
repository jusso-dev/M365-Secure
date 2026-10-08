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

    // Entra rejects the whole request if any one scope is unknown to the app or the resource
    // (AADSTS650053). Drop the named scope and try again so one stale name doesn't block sign-in;
    // the checks that need it will report Unknown and say so.
    // offline_access is what makes Entra issue a refresh token; without it every resource token
    // (Exchange, SharePoint admin, Azure, ...) is unobtainable after sign-in.
    let mut scopes: Vec<&str> = vec!["offline_access", "openid", "profile"];
    scopes.extend_from_slice(GRAPH_SCOPES);
    let dc: DeviceCodeResponse = loop {
        let scope = scopes.join(" ");
        let params = [("client_id", config.client_id.as_str()), ("scope", &scope)];
        let resp = client.post(&device_code_url).form(&params).send().await?;

        if resp.status().is_success() {
            break resp.json().await?;
        }
        let body: serde_json::Value = resp.json().await?;
        let description = body
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error")
            .to_string();
        match rejected_scope(&description) {
            Some(bad) if scopes.contains(&bad.as_str()) => {
                tracing::warn!(
                    "Entra does not recognise the scope '{}' for this app; continuing without it",
                    bad
                );
                println!(
                    "  {} scope '{}' not available to this app; continuing without it",
                    "note:".yellow(),
                    bad
                );
                scopes.retain(|s| *s != bad);
            }
            _ => anyhow::bail!("Failed to initiate device code flow: {}", description),
        }
    };

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
            if body.get("refresh_token").and_then(|v| v.as_str()).is_none() {
                println!(
                    "  {} Entra issued no refresh token; checks that read Exchange, SharePoint, Teams, Azure or Defender for Endpoint will report Unknown.",
                    "warning:".yellow()
                );
            }
            return Ok(TokenInfo {
                access_token: access_token.to_string(),
                refresh_token: body
                    .get("refresh_token")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                expires_at: Utc::now()
                    + chrono::Duration::seconds(body["expires_in"].as_i64().unwrap_or(3600)),
                tenant_id: config.tenant_id.clone(),
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
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

/// The scope name Entra names in an AADSTS650053 / AADSTS70011 error description, if any.
fn rejected_scope(description: &str) -> Option<String> {
    let start = description.find("scope '")? + "scope '".len();
    let end = description[start..].find('\'')? + start;
    let scope = &description[start..end];
    if scope.is_empty() || scope.contains(char::is_whitespace) {
        None
    } else {
        Some(scope.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::rejected_scope;

    #[test]
    fn extracts_scope_from_entra_error() {
        let msg =
            "AADSTS650053: The application 'Microsoft Graph Command Line Tools' asked for scope \
                   'InformationProtectionPolicy.Read.All' that doesn't exist on the resource \
                   '00000003-0000-0000-c000-000000000000'. Contact the app vendor.";
        assert_eq!(
            rejected_scope(msg).as_deref(),
            Some("InformationProtectionPolicy.Read.All")
        );
        assert_eq!(
            rejected_scope("AADSTS50020: user account does not exist"),
            None
        );
    }
}
