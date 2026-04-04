use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use tracing::{debug, info, warn};

use crate::backend::{RawSecret, SecretBackend};
use crate::types::*;

pub struct EngramBackend {
    client: Client,
    engram_url: String,
    engram_key: String,
}

impl EngramBackend {
    /// Create from environment variables.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            client: Client::new(),
            engram_url: std::env::var("ENGRAM_URL").context("ENGRAM_URL not set")?,
            engram_key: std::env::var("ENGRAM_API_KEY").context("ENGRAM_API_KEY not set")?,
        })
    }

    async fn fetch_all_memories(&self) -> Result<Vec<EngramMemory>> {
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

    async fn store_memory(&self, content: &str) -> Result<u64> {
        let resp = self.client
            .post(format!("{}/store", self.engram_url))
            .header("Authorization", format!("Bearer {}", self.engram_key))
            .json(&EngramStoreRequest {
                content: content.to_string(),
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
        Ok(r.id)
    }

    async fn delete_memory(&self, id: u64) -> Result<()> {
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

    /// Parse a [CRED:v3] line into service, key, ciphertext.
    fn parse_v3_line(content: &str) -> Option<(&str, &str, &str)> {
        let rest = content.strip_prefix("[CRED:v3] ")?;
        let eq_pos = rest.find(" = ")?;
        let path = &rest[..eq_pos];
        let ciphertext = &rest[eq_pos + 3..];
        let slash_pos = path.find('/')?;
        let service = &path[..slash_pos];
        let key = &path[slash_pos + 1..];
        Some((service, key, ciphertext))
    }

    /// Parse any [CRED], [CRED:v2], or [CRED:v3] line.
    /// Returns (service, key, ciphertext, is_legacy).
    fn parse_any_cred_line(content: &str) -> Option<(String, String, String, bool)> {
        if let Some((s, k, c)) = Self::parse_v3_line(content) {
            return Some((s.to_string(), k.to_string(), c.to_string(), false));
        }

        // v1: [CRED] service/key = ciphertext
        if let Some(rest) = content.strip_prefix("[CRED] ") {
            let eq_pos = rest.find(" = ")?;
            let path = &rest[..eq_pos];
            let ciphertext = &rest[eq_pos + 3..];
            let slash_pos = path.find('/')?;
            let service = &path[..slash_pos];
            let key = &path[slash_pos + 1..];
            return Some((service.to_string(), key.to_string(), ciphertext.to_string(), true));
        }

        // v2: [CRED:v2] service/key = ciphertext
        if let Some(rest) = content.strip_prefix("[CRED:v2] ") {
            let eq_pos = rest.find(" = ")?;
            let path = &rest[..eq_pos];
            let ciphertext = &rest[eq_pos + 3..];
            let slash_pos = path.find('/')?;
            let service = &path[..slash_pos];
            let key = &path[slash_pos + 1..];
            return Some((service.to_string(), key.to_string(), ciphertext.to_string(), true));
        }

        None
    }
}

#[async_trait]
impl SecretBackend for EngramBackend {
    async fn list_all(&self) -> Result<Vec<RawSecret>> {
        let memories = self.fetch_all_memories().await?;
        let mut secrets = Vec::new();

        for memory in &memories {
            if !memory.content.starts_with("[CRED") {
                continue;
            }

            if let Some((service, key, ciphertext, is_legacy)) =
                Self::parse_any_cred_line(&memory.content)
            {
                if is_legacy {
                    // Lazy migration: re-store as v3, delete old entry
                    let v3_content = format!("[CRED:v3] {}/{} = {}", service, key, ciphertext);
                    info!("migrating legacy entry {}/{} (engram_id={})", service, key, memory.id);
                    if let Ok(new_id) = self.store_memory(&v3_content).await {
                        let _ = self.delete_memory(memory.id).await;
                        secrets.push(RawSecret {
                            id: new_id,
                            service,
                            key,
                            ciphertext,
                            created_at: memory.created_at.clone(),
                        });
                    } else {
                        secrets.push(RawSecret {
                            id: memory.id,
                            service,
                            key,
                            ciphertext,
                            created_at: memory.created_at.clone(),
                        });
                    }
                } else {
                    secrets.push(RawSecret {
                        id: memory.id,
                        service,
                        key,
                        ciphertext,
                        created_at: memory.created_at.clone(),
                    });
                }
            }
        }

        secrets.sort_by(|a, b| (&a.service, &a.key).cmp(&(&b.service, &b.key)));
        Ok(secrets)
    }

    async fn store(&self, service: &str, key: &str, ciphertext: &str) -> Result<u64> {
        // Delete existing entries for this service/key
        let all = self.list_all().await.unwrap_or_default();
        for existing in all.iter().filter(|s| s.service == service && s.key == key) {
            debug!("replacing {}/{} (engram_id={})", service, key, existing.id);
            let _ = self.delete_memory(existing.id).await;
        }

        let content = format!("[CRED:v3] {}/{} = {}", service, key, ciphertext);
        let id = self.store_memory(&content).await?;
        debug!("stored {}/{} -> engram_id={}", service, key, id);
        Ok(id)
    }

    async fn get(&self, service: &str, key: &str) -> Result<RawSecret> {
        let all = self.list_all().await?;
        all.into_iter()
            .filter(|s| s.service == service && s.key == key)
            .max_by_key(|s| s.id)
            .ok_or_else(|| anyhow!("secret not found: {}/{}", service, key))
    }

    async fn delete(&self, service: &str, key: &str) -> Result<()> {
        let secret = self.get(service, key).await
            .map_err(|_| anyhow!("secret not found: {}/{}", service, key))?;
        self.delete_memory(secret.id).await
    }
}
