use anyhow::Result;
use std::path::PathBuf;

use super::TokenInfo;

#[derive(Clone)]
pub struct TokenCache {
    cache_path: PathBuf,
    #[allow(dead_code)]
    tenant_id: String,
}

impl TokenCache {
    pub fn new(tenant_id: &str) -> Self {
        let cache_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".m365-assess");

        Self {
            cache_path: cache_dir.join(format!("token_{}.json", tenant_id)),
            tenant_id: tenant_id.to_string(),
        }
    }

    pub fn save(&self, token: &TokenInfo) -> Result<()> {
        if let Some(parent) = self.cache_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Try macOS Keychain first
        #[cfg(target_os = "macos")]
        {
            if self.save_to_keychain(token).is_ok() {
                return Ok(());
            }
            tracing::warn!("Keychain save failed, falling back to file");
        }

        // Fallback: save to file with restricted permissions
        let json = serde_json::to_string_pretty(token)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.cache_path)?;
            use std::io::Write;
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(json.as_bytes())?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(&self.cache_path, json)?;
        }

        Ok(())
    }

    pub fn load(&self) -> Result<Option<TokenInfo>> {
        // Try macOS Keychain first
        #[cfg(target_os = "macos")]
        {
            if let Ok(Some(token)) = self.load_from_keychain() {
                return Ok(Some(token));
            }
        }

        // Fallback: load from file
        if !self.cache_path.exists() {
            return Ok(None);
        }

        let json = std::fs::read_to_string(&self.cache_path)?;
        let token: TokenInfo = serde_json::from_str(&json)?;
        Ok(Some(token))
    }

    pub fn clear(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let _ = self.delete_from_keychain();
        }

        if self.cache_path.exists() {
            std::fs::remove_file(&self.cache_path)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn save_to_keychain(&self, token: &TokenInfo) -> Result<()> {
        use security_framework::passwords::set_generic_password;
        let json = serde_json::to_string(token)?;
        set_generic_password("m365-assess", &self.tenant_id, json.as_bytes())
            .map_err(|e| anyhow::anyhow!("Keychain error: {}", e))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn load_from_keychain(&self) -> Result<Option<TokenInfo>> {
        use security_framework::passwords::get_generic_password;
        match get_generic_password("m365-assess", &self.tenant_id) {
            Ok(bytes) => {
                let json = String::from_utf8(bytes)?;
                let token: TokenInfo = serde_json::from_str(&json)?;
                Ok(Some(token))
            }
            Err(_) => Ok(None),
        }
    }

    #[cfg(target_os = "macos")]
    fn delete_from_keychain(&self) -> Result<()> {
        use security_framework::passwords::delete_generic_password;
        delete_generic_password("m365-assess", &self.tenant_id)
            .map_err(|e| anyhow::anyhow!("Keychain delete error: {}", e))?;
        Ok(())
    }
}
