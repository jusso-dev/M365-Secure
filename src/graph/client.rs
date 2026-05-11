use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::auth::AuthManager;

/// Microsoft Graph API client with rate limiting, retry, and pagination
#[derive(Clone)]
pub struct GraphClient {
    http: reqwest::Client,
    auth: AuthManager,
    base_url: String,
    semaphore: Arc<Semaphore>,
}

#[derive(serde::Deserialize, Debug)]
pub struct GraphResponse<T> {
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct GraphError {
    pub error: GraphErrorBody,
}

#[derive(serde::Deserialize, Debug)]
pub struct GraphErrorBody {
    pub code: String,
    pub message: String,
}

impl GraphClient {
    pub fn new(auth: AuthManager) -> Self {
        let base_url = auth.cloud().graph_endpoint().to_string();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .pool_max_idle_per_host(10)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            http,
            auth,
            base_url,
            semaphore: Arc::new(Semaphore::new(10)), // Max 10 concurrent requests
        }
    }

    /// GET a collection with automatic pagination
    pub async fn get_all<T: DeserializeOwned>(&self, endpoint: &str) -> Result<Vec<T>> {
        let mut results = Vec::new();
        let mut url = Some(self.build_url(endpoint));

        while let Some(current_url) = url {
            let response = self.execute_with_retry(&current_url, None).await?;
            let body = response.text().await?;

            let page: GraphResponse<T> = serde_json::from_str(&body).map_err(|e| {
                tracing::error!("Failed to parse paginated response: {}", e);
                anyhow::anyhow!("JSON parse error: {}", e)
            })?;

            results.extend(page.value);
            url = page.next_link;
        }

        Ok(results)
    }

    /// GET a collection with eventual consistency header (for sign-in activity, etc.)
    pub async fn get_all_eventual<T: DeserializeOwned>(&self, endpoint: &str) -> Result<Vec<T>> {
        let mut results = Vec::new();
        let mut url = Some(self.build_url(endpoint));

        while let Some(current_url) = url {
            let mut headers = HeaderMap::new();
            headers.insert("ConsistencyLevel", HeaderValue::from_static("eventual"));

            let response = self
                .execute_with_retry_headers(&current_url, None, headers)
                .await?;
            let body = response.text().await?;

            let page: GraphResponse<T> = serde_json::from_str(&body)?;
            results.extend(page.value);
            url = page.next_link;
        }

        Ok(results)
    }

    /// GET raw JSON value
    pub async fn get_json(&self, endpoint: &str) -> Result<serde_json::Value> {
        let url = self.build_url(endpoint);
        let response = self.execute_with_retry(&url, None).await?;
        let body: serde_json::Value = response.json().await?;

        if let Some(error) = body.get("error") {
            let code = error
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("Unknown");
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            anyhow::bail!("Graph API error [{}]: {}", code, msg);
        }

        Ok(body)
    }

    /// Invoke an Exchange Online PowerShell cmdlet via the Exchange Admin API.
    /// Uses POST to /adminapi/beta/{tenantId}/InvokeCommand with a CmdletInput body.
    /// Falls back to GET on the v2.0 REST-style endpoint if InvokeCommand fails.
    pub async fn exo_invoke_cmdlet(
        &self,
        tenant_id: &str,
        cmdlet_name: &str,
        parameters: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let _permit = self.semaphore.acquire().await?;

        let token = self.auth.get_exo_token().await?;

        // Try 1: POST InvokeCommand (works with Exchange Administrator role)
        let invoke_url = format!(
            "https://outlook.office365.com/adminapi/beta/{}/InvokeCommand",
            tenant_id
        );
        let body = serde_json::json!({
            "CmdletInput": {
                "CmdletName": cmdlet_name,
                "Parameters": parameters.unwrap_or(&serde_json::json!({}))
            }
        });

        let resp = self
            .http
            .post(&invoke_url)
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await;

        if let Ok(response) = resp {
            let status = response.status();
            if status.is_success() {
                if let Ok(json) = response.json::<serde_json::Value>().await {
                    return Ok(json);
                }
            } else {
                let body_text = response.text().await.unwrap_or_default();
                tracing::debug!(
                    "InvokeCommand failed ({}): {}",
                    status,
                    &body_text[..body_text.len().min(200)]
                );
            }
        }

        // Try 2: GET v2.0 REST-style endpoint (for supported resources)
        let resource_name = cmdlet_name.strip_prefix("Get-").unwrap_or(cmdlet_name);
        let rest_url = format!(
            "https://outlook.office365.com/adminapi/v2.0/{}/{}",
            tenant_id, resource_name
        );

        let token = self.auth.get_exo_token().await?;
        let resp = self
            .http
            .get(&rest_url)
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await;

        if let Ok(response) = resp {
            let status = response.status();
            if status.is_success() {
                if let Ok(json) = response.json::<serde_json::Value>().await {
                    return Ok(json);
                }
            } else {
                let body_text = response.text().await.unwrap_or_default();
                tracing::debug!(
                    "REST GET failed ({}): {}",
                    status,
                    &body_text[..body_text.len().min(200)]
                );
            }
        }

        anyhow::bail!(
            "Exchange cmdlet '{}' not available via REST API. This setting requires Exchange Online PowerShell.",
            cmdlet_name
        )
    }

    /// Legacy wrapper - calls exo_invoke_cmdlet and extracts the result.
    /// The `url` parameter is parsed to extract the resource name.
    pub async fn exo_get_json(&self, url: &str) -> Result<serde_json::Value> {
        // Extract tenant_id and resource from URL like:
        // https://outlook.office365.com/adminapi/beta/{tenant}/ResourceName
        let parts: Vec<&str> = url.rsplitn(2, '/').collect();
        let resource = parts.first().unwrap_or(&"");

        // Extract tenant_id from URL
        let tenant_id = url
            .split("/adminapi/")
            .nth(1)
            .and_then(|s| s.split('/').nth(1))
            .unwrap_or("");

        let cmdlet_name = format!("Get-{}", resource);
        self.exo_invoke_cmdlet(tenant_id, &cmdlet_name, None).await
    }

    fn build_url(&self, endpoint: &str) -> String {
        if endpoint.starts_with("https://") {
            endpoint.to_string()
        } else {
            format!("{}{}", self.base_url, endpoint)
        }
    }

    async fn execute_with_retry(
        &self,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::Response> {
        self.execute_with_retry_headers(url, body, HeaderMap::new())
            .await
    }

    async fn execute_with_retry_headers(
        &self,
        url: &str,
        body: Option<&serde_json::Value>,
        extra_headers: HeaderMap,
    ) -> Result<reqwest::Response> {
        let _permit = self.semaphore.acquire().await?;
        let max_retries = 3;
        let mut last_error = None;

        for attempt in 0..max_retries {
            if attempt > 0 {
                let delay = Duration::from_millis(1000 * 2u64.pow(attempt as u32));
                tracing::debug!("Retry attempt {} after {:?}", attempt + 1, delay);
                tokio::time::sleep(delay).await;
            }

            let token = self.auth.get_token().await?;
            let mut headers = extra_headers.clone();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token))?,
            );
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

            let request = if let Some(body) = body {
                self.http.post(url).headers(headers).json(body)
            } else {
                self.http.get(url).headers(headers)
            };

            match request.send().await {
                Ok(resp) => {
                    let status = resp.status();

                    // Rate limited - wait and retry
                    if status.as_u16() == 429 {
                        let retry_after = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(30);
                        tracing::warn!("Rate limited. Waiting {} seconds", retry_after);
                        tokio::time::sleep(Duration::from_secs(retry_after)).await;
                        continue;
                    }

                    // Server error - retry
                    if status.is_server_error() {
                        tracing::warn!("Server error {} on {}", status, url);
                        last_error = Some(anyhow::anyhow!("Server error: {}", status));
                        continue;
                    }

                    // Client error - don't retry (except 429 handled above)
                    if status.is_client_error() {
                        let body = resp.text().await?;
                        if let Ok(err) = serde_json::from_str::<GraphError>(&body) {
                            anyhow::bail!(
                                "Graph API error [{}]: {}",
                                err.error.code,
                                err.error.message
                            );
                        }
                        anyhow::bail!("HTTP {} for {}: {}", status, url, body);
                    }

                    return Ok(resp);
                }
                Err(e) => {
                    tracing::warn!("Request error on attempt {}: {}", attempt + 1, e);
                    last_error = Some(e.into());
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("Request failed after {} retries", max_retries)))
    }
}
