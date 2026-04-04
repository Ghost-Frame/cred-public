use aes_gcm::{Aes256Gcm, Key};
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use tracing::{debug, info, warn};

use crate::types::*;

pub struct CredStore {
    client: Client,
    engram_url: String,
    engram_key: String,
    master_key: Option<Key<Aes256Gcm>>,
}

impl CredStore {
    pub fn with_key(master_key: Key<Aes256Gcm>) -> Result<Self> {
        Ok(Self {
            client: Client::new(),
            engram_url: std::env::var("ENGRAM_URL").context("ENGRAM_URL not set")?,
            engram_key: std::env::var("ENGRAM_API_KEY").context("ENGRAM_API_KEY not set")?,
            master_key: Some(master_key),
        })
    }

    fn require_key(&self) -> Result<&Key<Aes256Gcm>> {
        self.master_key.as_ref()
            .ok_or_else(|| anyhow!("no encryption key -- is the YubiKey plugged in?"))
    }

    async fn fetch_all_raw(&self) -> Result<Vec<EngramMemory>> {
        let resp = self.client
            .get(format!("{}/list", self.engram_url))
            .header("Authorization", format!("Bearer {}", self.engram_key))
            .query(&[("category", "credential"), ("limit", "500")])
            .send().await.context("failed to reach Engram")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Engram list failed ({}): {}", status, body));
        }

        Ok(resp.json::<EngramListResponse>().await?.results)
    }

    /// Fetch, parse, and lazy-migrate all secrets.
    /// v1/v2 entries are re-stored as v3 and the old entry deleted.
    pub async fn list_all(&self) -> Result<Vec<Secret>> {
        let master_key = self.require_key()?;
        let raw = self.fetch_all_raw().await?;
        let mut secrets = Vec::new();

        for memory in &raw {
            if !memory.content.starts_with("[CRED") { continue; }

            let is_legacy = memory.content.starts_with("[CRED] ") || memory.content.starts_with("[CRED:v2] ");

            if let Some(secret) = Secret::from_engram_content(&memory.content, memory.id, Some(master_key)) {
                if is_legacy {
                    // Lazy migration: re-store as v3, delete old entry
                    info!("migrating legacy entry {}/{} (engram_id={})", secret.service, secret.key, memory.id);
                    if let Ok(new_id) = self.store_raw(&secret).await {
                        let _ = self.delete_by_id(memory.id).await;
                        let mut migrated = secret;
                        migrated.engram_id = Some(new_id);
                        secrets.push(migrated);
                    } else {
                        secrets.push(secret); // Migration failed, return as-is
                    }
                } else {
                    secrets.push(secret);
                }
            }
        }

        secrets.sort_by(|a, b| (&a.service, &a.key).cmp(&(&b.service, &b.key)));
        Ok(secrets)
    }

    /// Store a secret. Replaces ALL existing entries for the same service/key.
    pub async fn store(&self, secret: &Secret) -> Result<u64> {
        // Delete ALL existing entries for this service/key (handles duplicates)
        if let Ok(all) = self.list_all().await {
            for existing in all.iter().filter(|s| s.service == secret.service && s.key == secret.key) {
                if let Some(id) = existing.engram_id {
                    debug!("replacing {}/{} (engram_id={})", secret.service, secret.key, id);
                    let _ = self.delete_by_id(id).await;
                }
            }
        }
        self.store_raw(secret).await
    }

    async fn store_raw(&self, secret: &Secret) -> Result<u64> {
        let master_key = self.require_key()?;
        let content = secret.to_engram_content(master_key)?;

        let resp = self.client
            .post(format!("{}/store", self.engram_url))
            .header("Authorization", format!("Bearer {}", self.engram_key))
            .json(&EngramStoreRequest {
                content,
                category: "credential".to_string(),
                source: "cred".to_string(),
                importance: Some(9),
                is_static: Some(true),
            })
            .send().await.context("failed to reach Engram")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Engram store failed ({}): {}", status, body));
        }

        let r: EngramStoreResponse = resp.json().await?;
        debug!("stored {}/{} -> engram_id={}", secret.service, secret.key, r.id);
        Ok(r.id)
    }

    pub async fn get(&self, service: &str, key: &str) -> Result<Secret> {
        let all = self.list_all().await?;
        all.into_iter()
            .filter(|s| s.service == service && s.key == key)
            .max_by_key(|s| s.engram_id.unwrap_or(0))
            .ok_or_else(|| anyhow!("secret not found: {}/{}", service, key))
    }

    pub async fn delete(&self, service: &str, key: &str) -> Result<()> {
        let secret = self.get(service, key).await
            .map_err(|_| anyhow!("secret not found: {}/{}", service, key))?;
        let id = secret.engram_id
            .ok_or_else(|| anyhow!("secret has no engram_id"))?;
        self.delete_by_id(id).await
    }

    async fn delete_by_id(&self, id: u64) -> Result<()> {
        let resp = self.client
            .delete(format!("{}/memory/{}", self.engram_url, id))
            .header("Authorization", format!("Bearer {}", self.engram_key))
            .send().await.context("failed to reach Engram")?;

        if resp.status().as_u16() == 404 {
            warn!("engram memory {} already deleted", id);
            return Ok(());
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Engram delete failed ({}): {}", status, body));
        }

        debug!("deleted engram memory {}", id);
        Ok(())
    }
}
