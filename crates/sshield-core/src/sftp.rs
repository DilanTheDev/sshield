//! SFTP backend for the dual-pane file browser.

use crate::ssh::{Connection, SshError};
use russh_sftp::client::SftpSession;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Result<T> = std::result::Result<T, SshError>;

fn e<E: std::fmt::Display>(x: E) -> SshError {
    SshError::Msg(format!("sftp: {x}"))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified: Option<u64>,
    pub perms: String,
}

pub struct Sftp {
    s: SftpSession,
}

/// Shared byte counter for progress bars.
pub type Progress = Arc<AtomicU64>;

impl Sftp {
    pub async fn open(conn: &Connection) -> Result<Sftp> {
        let ch = conn.handle.channel_open_session().await?;
        ch.request_subsystem(true, "sftp").await?;
        let s = SftpSession::new(ch.into_stream()).await.map_err(e)?;
        Ok(Sftp { s })
    }

    pub async fn home(&self) -> Result<String> {
        self.s.canonicalize(".").await.map_err(e)
    }

    /// Directories first, then case-insensitive by name.
    pub async fn list(&self, dir: &str) -> Result<Vec<Entry>> {
        let mut out = vec![];
        for ent in self.s.read_dir(dir).await.map_err(e)? {
            let name = ent.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let m = ent.metadata();
            let ft = ent.file_type();
            out.push(Entry {
                path: join(dir, &name),
                name,
                is_dir: ft.is_dir(),
                is_symlink: ft.is_symlink(),
                size: m.len(),
                modified: m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
                perms: m.permissions().to_string(),
            });
        }
        sort_entries(&mut out);
        Ok(out)
    }

    pub async fn download(&self, remote: &str, local: &Path, progress: Option<Progress>) -> Result<u64> {
        let mut src = self.s.open(remote).await.map_err(e)?;
        let mut dst = tokio::fs::File::create(local).await?;
        copy_counted(&mut src, &mut dst, progress).await
    }

    pub async fn upload(&self, local: &Path, remote: &str, progress: Option<Progress>) -> Result<u64> {
        let mut src = tokio::fs::File::open(local).await?;
        let mut dst = self.s.create(remote).await.map_err(e)?;
        let n = copy_counted(&mut src, &mut dst, progress).await?;
        dst.shutdown().await?;
        Ok(n)
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.s.create_dir(path).await.map_err(e)
    }
    pub async fn remove_file(&self, path: &str) -> Result<()> {
        self.s.remove_file(path).await.map_err(e)
    }
    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        self.s.remove_dir(path).await.map_err(e)
    }
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.s.rename(from, to).await.map_err(e)
    }
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.s.read(path).await.map_err(e)
    }
    /// Create or truncate `path` and write `data` (russh-sftp's own `write` requires an existing file).
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let mut f = self.s.create(path).await.map_err(e)?;
        f.write_all(data).await?;
        f.shutdown().await?;
        Ok(())
    }

    /// Recursively delete a directory tree.
    pub fn remove_tree<'a>(&'a self, path: &'a str) -> futures::future::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            for ent in self.list(path).await? {
                if ent.is_dir && !ent.is_symlink {
                    self.remove_tree(&ent.path).await?;
                } else {
                    self.remove_file(&ent.path).await?;
                }
            }
            self.remove_dir(path).await
        })
    }

    pub async fn close(&self) {
        let _ = self.s.close().await;
    }
}

async fn copy_counted<R, W>(r: &mut R, w: &mut W, progress: Option<Progress>) -> Result<u64>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
        if let Some(p) = &progress {
            p.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
    w.flush().await?;
    Ok(total)
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

/// Parent of a POSIX path ("/" stays "/").
pub fn parent(path: &str) -> String {
    let t = path.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => t[..i].to_string(),
    }
}

pub fn sort_entries(v: &mut [Entry]) {
    v.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths() {
        assert_eq!(join("/a", "b"), "/a/b");
        assert_eq!(join("/", "b"), "/b");
        assert_eq!(parent("/a/b/"), "/a");
        assert_eq!(parent("/a"), "/");
        assert_eq!(parent("/"), "/");
    }
}
