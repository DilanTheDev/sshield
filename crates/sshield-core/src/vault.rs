//! Encrypted library storage.
//!
//! File layout (JSON envelope, versioned):
//! ```json
//! {"v":1,"kdf":"argon2id","m_kib":65536,"t":3,"p":1,"salt":"..","nonce":"..","ct":".."}
//! ```
//! The key is derived with Argon2id from the master password; the payload is
//! sealed with XChaCha20-Poly1305 (the header fields are bound as AAD).
//! Because the whole library (host names, usernames, keys, passwords) is
//! inside the ciphertext, the file is safe to put in any cloud folder.

use crate::model::Library;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("wrong master password or corrupted vault")]
    BadPassword,
    #[error("vault file is malformed: {0}")]
    Malformed(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(String),
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    kdf: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
    nonce: String,
    ct: String,
}

impl Envelope {
    fn aad(&self) -> Vec<u8> {
        format!("sshield|{}|{}|{}|{}|{}|{}", self.v, self.kdf, self.m_kib, self.t, self.p, self.salt)
            .into_bytes()
    }
}

/// KDF cost. Tests use a cheap profile; production uses 64 MiB / 3 passes.
#[derive(Clone, Copy, Debug)]
pub struct KdfCost {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}
impl KdfCost {
    pub const STRONG: KdfCost = KdfCost { m_kib: 64 * 1024, t: 3, p: 1 };
    pub const FAST_FOR_TESTS: KdfCost = KdfCost { m_kib: 64, t: 1, p: 1 };
}

fn derive(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| VaultError::Crypto(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    Ok(key)
}

/// An unlocked vault: holds the derived key so saves don't re-run the KDF.
pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    cost: KdfCost,
    /// Optional mirror directory (cloud-sync folder).
    mirror: Option<PathBuf>,
}

impl Vault {
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Create a new vault protected by `password` and write `lib` to it.
    pub fn create(path: &Path, password: &str, lib: &Library, cost: KdfCost) -> Result<Vault, VaultError> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| VaultError::Crypto(e.to_string()))?;
        let key = derive(password, &salt, cost.m_kib, cost.t, cost.p)?;
        let v = Vault { path: path.to_path_buf(), key, salt, cost, mirror: None };
        v.save(lib)?;
        Ok(v)
    }

    pub fn unlock(path: &Path, password: &str) -> Result<(Vault, Library), VaultError> {
        let raw = std::fs::read(path)?;
        let env: Envelope = serde_json::from_slice(&raw).map_err(|e| VaultError::Malformed(e.to_string()))?;
        if env.v != 1 || env.kdf != "argon2id" {
            return Err(VaultError::Malformed(format!("unsupported version/kdf {}/{}", env.v, env.kdf)));
        }
        // Refuse absurd parameters from a tampered file (memory DoS).
        if env.m_kib > 1024 * 1024 || env.t > 20 || env.p > 16 {
            return Err(VaultError::Malformed("kdf parameters out of range".into()));
        }
        let dec = |s: &str| B64.decode(s).map_err(|e| VaultError::Malformed(e.to_string()));
        let salt_v = dec(&env.salt)?;
        let nonce = dec(&env.nonce)?;
        let ct = dec(&env.ct)?;
        if nonce.len() != 24 || salt_v.len() != 16 {
            return Err(VaultError::Malformed("bad nonce/salt length".into()));
        }
        let key = derive(password, &salt_v, env.m_kib, env.t, env.p)?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| VaultError::Malformed("nonce".into()))?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let pt = cipher
            .decrypt((&nonce).into(), Payload { msg: &ct, aad: &env.aad() })
            .map_err(|_| VaultError::BadPassword)?;
        let pt = Zeroizing::new(pt);
        let lib: Library = serde_json::from_slice(&pt).map_err(|e| VaultError::Malformed(e.to_string()))?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_v);
        let vault = Vault {
            path: path.to_path_buf(),
            key,
            salt,
            cost: KdfCost { m_kib: env.m_kib, t: env.t, p: env.p },
            mirror: None,
        };
        Ok((vault, lib))
    }

    pub fn set_mirror(&mut self, dir: Option<PathBuf>) {
        self.mirror = dir;
    }

    /// Encrypt with a fresh nonce and atomically replace the file.
    pub fn save(&self, lib: &Library) -> Result<(), VaultError> {
        let pt = Zeroizing::new(serde_json::to_vec(lib).map_err(|e| VaultError::Malformed(e.to_string()))?);
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| VaultError::Crypto(e.to_string()))?;
        let mut env = Envelope {
            v: 1,
            kdf: "argon2id".into(),
            m_kib: self.cost.m_kib,
            t: self.cost.t,
            p: self.cost.p,
            salt: B64.encode(self.salt),
            nonce: B64.encode(nonce),
            ct: String::new(),
        };
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let ct = cipher
            .encrypt((&nonce).into(), Payload { msg: &pt, aad: &env.aad() })
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        env.ct = B64.encode(ct);
        let bytes = serde_json::to_vec_pretty(&env).map_err(|e| VaultError::Malformed(e.to_string()))?;
        write_atomic(&self.path, &bytes)?;
        if let Some(dir) = &self.mirror {
            if let Err(e) = std::fs::create_dir_all(dir)
                .and_then(|_| write_atomic(&dir.join(self.path.file_name().unwrap_or_default()), &bytes))
            {
                // Mirror failures must not lose the local save.
                eprintln!("sshield: vault mirror failed: {e}");
            }
        }
        Ok(())
    }

    /// Re-key under a new password (new salt).
    pub fn change_password(&mut self, new_password: &str, lib: &Library) -> Result<(), VaultError> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| VaultError::Crypto(e.to_string()))?;
        self.key = derive(new_password, &salt, self.cost.m_kib, self.cost.t, self.cost.p)?;
        self.salt = salt;
        self.save(lib)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)
}

/// Default location of the app's data directory.
pub fn data_dir() -> PathBuf {
    dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("sshield")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn tmp(name: &str) -> PathBuf {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).unwrap();
        std::env::temp_dir().join(format!("sshield-test-{name}-{:?}", b)).join("vault.json")
    }

    fn lib() -> Library {
        let mut l = Library::default();
        let mut h = Host::new("prod", "10.0.0.5", "root");
        h.auth = Auth::Password { password: "hunter2-secret".into() };
        l.hosts.push(h);
        l
    }

    #[test]
    fn roundtrip_and_no_plaintext_on_disk() {
        let p = tmp("rt");
        let l = lib();
        Vault::create(&p, "correct horse", &l, KdfCost::FAST_FOR_TESTS).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("hunter2-secret") && !raw.contains("10.0.0.5") && !raw.contains("prod"));
        let (_, l2) = Vault::unlock(&p, "correct horse").unwrap();
        assert_eq!(l, l2);
    }

    #[test]
    fn wrong_password_and_tamper_detected() {
        let p = tmp("bad");
        Vault::create(&p, "pw", &lib(), KdfCost::FAST_FOR_TESTS).unwrap();
        assert!(matches!(Vault::unlock(&p, "nope"), Err(VaultError::BadPassword)));
        // flip header param bound as AAD
        let raw = std::fs::read_to_string(&p).unwrap().replace("\"t\": 1", "\"t\": 2");
        std::fs::write(&p, raw).unwrap();
        assert!(Vault::unlock(&p, "pw").is_err());
    }

    #[test]
    fn change_password_and_mirror() {
        let p = tmp("chg");
        let mirror = p.parent().unwrap().join("cloud");
        let l = lib();
        let mut v = Vault::create(&p, "old", &l, KdfCost::FAST_FOR_TESTS).unwrap();
        v.set_mirror(Some(mirror.clone()));
        v.change_password("new", &l).unwrap();
        assert!(Vault::unlock(&p, "old").is_err());
        assert!(Vault::unlock(&p, "new").is_ok());
        assert!(Vault::unlock(&mirror.join("vault.json"), "new").is_ok());
    }

    #[test]
    fn rejects_hostile_kdf_params() {
        let p = tmp("dos");
        Vault::create(&p, "pw", &lib(), KdfCost::FAST_FOR_TESTS).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap().replace("\"m_kib\": 64", "\"m_kib\": 4000000");
        std::fs::write(&p, raw).unwrap();
        assert!(matches!(Vault::unlock(&p, "pw"), Err(VaultError::Malformed(_))));
    }
}
