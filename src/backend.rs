use anyhow::Result;
use async_trait::async_trait;

/// A raw secret as stored in the backend -- opaque ciphertext, no decryption.
#[derive(Debug, Clone)]
pub struct RawSecret {
    pub id: u64,
    pub service: String,
    pub key: String,
    pub ciphertext: String,
    pub created_at: Option<String>,
}

/// Storage backend for encrypted secrets.
/// Backends deal only in opaque ciphertext strings.
/// Encryption/decryption is handled by CredStore, not the backend.
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// List all stored secrets.
    async fn list_all(&self) -> Result<Vec<RawSecret>>;

    /// Store a secret. If a secret with the same service/key exists, replace it.
    /// Returns the new ID.
    async fn store(&self, service: &str, key: &str, ciphertext: &str) -> Result<u64>;

    /// Get a single secret by service and key.
    async fn get(&self, service: &str, key: &str) -> Result<RawSecret>;

    /// Delete a secret by service and key.
    async fn delete(&self, service: &str, key: &str) -> Result<()>;
}

/// Determine which backend to use based on environment variables.
///
/// Priority:
/// 1. CRED_BACKEND=sqlite -> SqliteBackend
/// 2. CRED_BACKEND=engram -> EngramBackend (fails if env vars missing)
/// 3. If ENGRAM_URL and ENGRAM_API_KEY are both set -> EngramBackend
/// 4. Otherwise -> SqliteBackend
pub fn create_backend() -> Result<Box<dyn SecretBackend>> {
    let explicit = std::env::var("CRED_BACKEND").ok();

    match explicit.as_deref() {
        Some("sqlite") => {
            let path = sqlite_db_path();
            tracing::info!("backend: sqlite (explicit) at {}", path.display());
            Ok(Box::new(crate::backend_sqlite::SqliteBackend::open(&path)?))
        }
        Some("engram") => {
            tracing::info!("backend: engram (explicit)");
            Ok(Box::new(crate::backend_engram::EngramBackend::from_env()?))
        }
        Some(other) => anyhow::bail!("unknown CRED_BACKEND value: {}", other),
        None => {
            // Auto-detect
            let has_engram = std::env::var("ENGRAM_URL").is_ok()
                && std::env::var("ENGRAM_API_KEY").is_ok();

            if has_engram {
                tracing::info!("backend: engram (auto-detected)");
                Ok(Box::new(crate::backend_engram::EngramBackend::from_env()?))
            } else {
                let path = sqlite_db_path();
                tracing::info!("backend: sqlite (auto-detected) at {}", path.display());
                Ok(Box::new(crate::backend_sqlite::SqliteBackend::open(&path)?))
            }
        }
    }
}

fn sqlite_db_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CRED_DB_PATH") {
        return std::path::PathBuf::from(p);
    }

    let config = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            std::path::PathBuf::from(home).join(".config")
        });

    config.join("cred").join("vault.db")
}
