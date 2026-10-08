use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::auth::{AuthManager, Resource};

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

    /// GET JSON from any Microsoft API that accepts a bearer token for `resource`
    /// (Azure Resource Manager, SharePoint admin, Teams admin, Defender for Endpoint).
    /// Error bodies in the Graph/ARM `{"error": {...}}` shape become `Err` with the code and message.
    /// Prefer the Junction gateway (`crate::junction`) for catalogued APIs; use this for endpoints it doesn't carry.
    pub async fn get_resource_json(
        &self,
        resource: Resource,
        url: &str,
    ) -> Result<serde_json::Value> {
        self.resource_request(resource, url, None, HeaderMap::new())
            .await
    }

    /// POST JSON to any Microsoft API that accepts a bearer token for `resource`.
    pub async fn post_resource_json(
        &self,
        resource: Resource,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.resource_request(resource, url, Some(body), HeaderMap::new())
            .await
    }

    /// Follow `@odata.nextLink` / `nextLink` paging on a resource API and return the concatenated `value` arrays.
    pub async fn get_resource_all(
        &self,
        resource: Resource,
        url: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let mut out = Vec::new();
        let mut next = Some(url.to_string());
        let mut pages = 0;
        while let Some(u) = next {
            let page = self.get_resource_json(resource, &u).await?;
            match page.get("value").and_then(|v| v.as_array()) {
                Some(items) => out.extend(items.iter().cloned()),
                None => match page.as_array() {
                    Some(items) => out.extend(items.iter().cloned()),
                    None => out.push(page.clone()),
                },
            }
            next = page
                .get("@odata.nextLink")
                .or_else(|| page.get("nextLink"))
                .and_then(|v| v.as_str())
                .map(String::from);
            pages += 1;
            if pages > 500 {
                anyhow::bail!("Paging did not terminate for {}", url);
            }
        }
        Ok(out)
    }

    async fn resource_request(
        &self,
        resource: Resource,
        url: &str,
        body: Option<&serde_json::Value>,
        extra_headers: HeaderMap,
    ) -> Result<serde_json::Value> {
        let _permit = self.semaphore.acquire().await?;
        let mut last_error = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt as u32))).await;
            }
            let token = self.auth.get_resource_token(resource).await?;
            let mut headers = extra_headers.clone();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token))?,
            );
            if !headers.contains_key(CONTENT_TYPE) {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            let request = match body {
                Some(b) => self.http.post(url).headers(headers).json(b),
                None => self.http.get(url).headers(headers),
            };
            match request.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.as_u16() == 429 || status.is_server_error() {
                        let retry_after = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(5);
                        tracing::warn!(
                            "{} returned {} for {}; retrying in {}s",
                            resource.display_name(),
                            status,
                            url,
                            retry_after
                        );
                        tokio::time::sleep(Duration::from_secs(retry_after)).await;
                        last_error = Some(anyhow::anyhow!("{} for {}", status, url));
                        continue;
                    }
                    let text = resp.text().await?;
                    if status.is_client_error() {
                        let detail = serde_json::from_str::<serde_json::Value>(&text)
                            .ok()
                            .and_then(|v| {
                                let e = v.get("error")?;
                                let code = e.get("code").and_then(|c| c.as_str()).unwrap_or("");
                                let msg = e
                                    .get("message")
                                    .and_then(|m| {
                                        m.as_str().map(String::from).or_else(|| {
                                            m.get("value")
                                                .and_then(|x| x.as_str())
                                                .map(String::from)
                                        })
                                    })
                                    .unwrap_or_default();
                                Some(format!("[{}] {}", code, msg))
                            })
                            .unwrap_or_else(|| text.chars().take(300).collect());
                        anyhow::bail!(
                            "{} error {} for {}: {}",
                            resource.display_name(),
                            status,
                            url,
                            detail
                        );
                    }
                    if text.trim().is_empty() {
                        return Ok(serde_json::Value::Null);
                    }
                    return serde_json::from_str(&text).map_err(|e| {
                        anyhow::anyhow!(
                            "JSON parse error from {} ({}): {}",
                            resource.display_name(),
                            url,
                            e
                        )
                    });
                }
                Err(e) => last_error = Some(e.into()),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Request to {} failed", url)))
    }

    /// The authentication manager behind this client (shared with the Junction gateway).
    pub fn auth(&self) -> &AuthManager {
        &self.auth
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
