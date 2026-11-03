//! sshield-core: everything that is not UI.
//!
//! * [`model`]     – hosts, groups, identities, snippets, settings
//! * [`vault`]     – Argon2id + XChaCha20-Poly1305 encrypted library file
//! * [`vpn`]       – OpenVPN / WireGuard enforcement ("SSH only via the tunnel")
//! * [`ssh`]       – connections, jump hosts, shell sessions, exec
//! * [`forward`]   – local / remote / dynamic (SOCKS5) port forwarding
//! * [`sftp`]      – file browser backend
//! * [`sshconfig`] – import from `~/.ssh/config`

#[cfg(feature = "devserver")]
pub mod devserver;
pub mod forward;
pub mod model;
pub mod sftp;
pub mod ssh;
pub mod sshconfig;
pub mod vault;
pub mod vpn;

pub use model::*;
pub use russh;
