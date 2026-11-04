//! Zero-knowledge sync client.
//!
//! What goes to the server is the already-encrypted vault file (XChaCha20-Poly1305,
//! key from Argon2id over the master password). The server only ever sees ciphertext.
//! Requests are authorised by a bearer token derived from `account` + master password
//! with a *different* Argon2id salt than the vault key, so the token reveals nothing
//! usable for decrypting the vault. The server stores blobs under `sha256(token)`.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SyncConfig {
    /// Base URL of the sync server, e.g. https://sshield-sync.example.workers.dev
    pub url: String,
    pub account: String,
    /// Bearer token from [`derive_token`]. Stored locally (0600), never in the vault.
    pub token: String,
    /// Server revision this device last pulled or pushed.
    pub rev: u64,
    /// Local changes not yet uploaded.
    pub pending: bool,
}

impl SyncConfig {
    pub fn enabled(&self) -> bool {
        !self.url.is_empty() && !self.token.is_empty()
    }

    fn path(dir: &Path) -> PathBuf {
        dir.join("sync.json")
    }

    pub fn load(dir: &Path) -> SyncConfig {
        std::fs::read(Self::path(dir))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let p = Self::path(dir);
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(tmp, p)
    }
}

/// Argon2id cost for the auth token: deliberately the same as the vault's own KDF
/// (64 MiB, 3 passes). The server stores a hash of this token, so if it were cheaper than the
/// vault KDF it would become the easiest way to guess a master password offline.
const TOKEN_M_KIB: u32 = 64 * 1024;
const TOKEN_T: u32 = 3;

/// Derive the 32-byte (hex) auth token. Deterministic, so every device computes the same one.
pub fn derive_token(password: &str, account: &str) -> Result<String, String> {
    derive_token_with(password, account, TOKEN_M_KIB, TOKEN_T)
}

fn derive_token_with(password: &str, account: &str, m_kib: u32, t: u32) -> Result<String, String> {
    let account = account.trim().to_lowercase();
    if account.is_empty() {
        return Err("account name is required".into());
    }
    // v2: stronger KDF than v1 (19 MiB / 2 passes). A different salt means v1 tokens never collide.
    let salt = format!("sshield-sync-v2|{account}");
    let params = Params::new(m_kib, t, 1, Some(32)).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Debug, PartialEq)]
pub enum Push {
    Ok(u64),
    /// Someone else pushed first; the server is at this revision.
    Conflict(u64),
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .user_agent(concat!("sshield/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn endpoint(cfg: &SyncConfig) -> String {
    format!("{}/v1/vault", cfg.url.trim_end_matches('/'))
}

fn rev_of(resp: &ureq::http::Response<ureq::Body>) -> u64 {
    resp.headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim_matches('"').parse().ok())
        .unwrap_or(0)
}

fn status_err(code: u16, what: &str) -> String {
    match code {
        401 | 403 => format!("{what}: server rejected the account/password (HTTP {code})"),
        413 => format!("{what}: vault is too large for the server"),
        429 => format!("{what}: rate limited, try again later"),
        _ => format!("{what}: server returned HTTP {code}"),
    }
}

/// Current server revision (`None` if nothing has been uploaded yet).
pub fn head(cfg: &SyncConfig) -> Result<Option<u64>, String> {
    let r = agent()
        .head(endpoint(cfg))
        .header("Authorization", format!("Bearer {}", cfg.token))
        .call()
        .map_err(|e| e.to_string())?;
    match r.status().as_u16() {
        200 => Ok(Some(rev_of(&r))),
        404 => Ok(None),
        c => Err(status_err(c, "check")),
    }
}

/// Download the encrypted vault. `None` if the account has nothing stored yet.
pub fn pull(cfg: &SyncConfig) -> Result<Option<(u64, Vec<u8>)>, String> {
    let mut r = agent()
        .get(endpoint(cfg))
        .header("Authorization", format!("Bearer {}", cfg.token))
        .call()
        .map_err(|e| e.to_string())?;
    match r.status().as_u16() {
        200 => {
            let rev = rev_of(&r);
            let body = r
                .body_mut()
                .with_config()
                .limit(2 * 1024 * 1024)
                .read_to_vec()
                .map_err(|e| e.to_string())?;
            Ok(Some((rev, body)))
        }
        404 => Ok(None),
        c => Err(status_err(c, "download")),
    }
}

/// Upload. `base_rev` is the revision this device last saw (0 = expect empty); the server
/// refuses with a conflict if it moved on, unless `force` is set.
pub fn push(cfg: &SyncConfig, bytes: &[u8], base_rev: u64, force: bool) -> Result<Push, String> {
    let mut req = agent()
        .put(endpoint(cfg))
        .header("Authorization", format!("Bearer {}", cfg.token))
        .header("Content-Type", "application/json");
    req = if force {
        req.header("If-Match", "*")
    } else {
        req.header("If-Match", format!("\"{base_rev}\""))
    };
    let mut r = req.send(bytes).map_err(|e| e.to_string())?;
    match r.status().as_u16() {
        200 | 201 => Ok(Push::Ok(rev_of(&r))),
        409 | 412 => {
            let rev = r
                .body_mut()
                .read_to_string()
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|v| v.get("rev")?.as_u64())
                .unwrap_or(0);
            Ok(Push::Conflict(rev))
        }
        c => Err(status_err(c, "upload")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_deterministic_and_account_scoped() {
        let a = derive_token_with("pw", "Me@Example.com ", 64, 1).unwrap();
        assert_eq!(a, derive_token_with("pw", "me@example.com", 64, 1).unwrap());
        assert_ne!(
            a,
            derive_token_with("pw2", "me@example.com", 64, 1).unwrap()
        );
        assert_ne!(a, derive_token_with("pw", "other", 64, 1).unwrap());
        assert_eq!(a.len(), 64);
        assert!(derive_token_with("pw", " ", 64, 1).is_err());
    }

    #[test]
    fn token_cost_is_not_weaker_than_the_vault_kdf() {
        let v = crate::vault::KdfCost::STRONG;
        assert!(TOKEN_M_KIB >= v.m_kib && TOKEN_T >= v.t);
    }

    #[test]
    fn config_roundtrip() {
        let d = std::env::temp_dir().join(format!("sshield-sync-test-{}", std::process::id()));
        let c = SyncConfig {
            url: "https://x".into(),
            account: "a".into(),
            token: "t".into(),
            rev: 3,
            pending: true,
        };
        c.save(&d).unwrap();
        assert_eq!(SyncConfig::load(&d), c);
        let _ = std::fs::remove_dir_all(&d);
    }
}
