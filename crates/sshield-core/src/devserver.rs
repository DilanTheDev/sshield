//! Test / demo support (feature `devserver`): an SFTP server confined to a directory.
//! Not part of the shipped client.

use russh_sftp::protocol::{Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub struct FsSftp {
    root: PathBuf,
    files: HashMap<String, tokio::fs::File>,
    dirs: HashMap<String, Option<Vec<File>>>,
    n: u32,
}

impl FsSftp {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FsSftp { root: root.into(), files: HashMap::new(), dirs: HashMap::new(), n: 0 }
    }

    /// Map a virtual absolute path onto the sandbox; refuse anything that escapes it.
    fn real(&self, p: &str) -> Result<PathBuf, StatusCode> {
        let mut out = self.root.clone();
        for c in Path::new(p).components() {
            match c {
                Component::Normal(s) => out.push(s),
                Component::RootDir | Component::CurDir => {}
                _ => return Err(StatusCode::PermissionDenied),
            }
        }
        Ok(out)
    }

    fn handle(&mut self) -> String {
        self.n += 1;
        format!("h{}", self.n)
    }
}

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en".into() }
}

fn io(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl russh_sftp::server::Handler for FsSftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _v: u32, _e: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        // normalise "." and relative paths to an absolute virtual path
        let mut parts: Vec<String> = vec![];
        for c in Path::new(&path).components() {
            match c {
                Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
                Component::ParentDir => {
                    parts.pop();
                }
                _ => {}
            }
        }
        Ok(Name { id, files: vec![File::dummy(format!("/{}", parts.join("/")))] })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let dir = self.real(&path)?;
        let mut rd = tokio::fs::read_dir(&dir).await.map_err(io)?;
        let mut files = vec![];
        while let Some(e) = rd.next_entry().await.map_err(io)? {
            let md = e.metadata().await.map_err(io)?;
            files.push(File::new(e.file_name().to_string_lossy(), FileAttributes::from(&md)));
        }
        let h = self.handle();
        self.dirs.insert(h.clone(), Some(files));
        Ok(Handle { id, handle: h })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.dirs.get_mut(&handle).and_then(Option::take) {
            Some(files) => Ok(Name { id, files }),
            None => Err(StatusCode::Eof),
        }
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let md = tokio::fs::metadata(self.real(&path)?).await.map_err(io)?;
        Ok(russh_sftp::protocol::Attrs { id, attrs: FileAttributes::from(&md) })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let md = tokio::fs::symlink_metadata(self.real(&path)?).await.map_err(io)?;
        Ok(russh_sftp::protocol::Attrs { id, attrs: FileAttributes::from(&md) })
    }

    async fn open(&mut self, id: u32, filename: String, pflags: OpenFlags, _a: FileAttributes) -> Result<Handle, Self::Error> {
        let p = self.real(&filename)?;
        let std_opts: std::fs::OpenOptions = pflags.into();
        let f = tokio::fs::OpenOptions::from(std_opts).open(p).await.map_err(io)?;
        let h = self.handle();
        self.files.insert(h.clone(), f);
        Ok(Handle { id, handle: h })
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let f = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        f.seek(SeekFrom::Start(offset)).await.map_err(io)?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read(&mut buf).await.map_err(io)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        let f = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        f.seek(SeekFrom::Start(offset)).await.map_err(io)?;
        f.write_all(&data).await.map_err(io)?;
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        if let Some(mut f) = self.files.remove(&handle) {
            let _ = f.flush().await;
        }
        self.dirs.remove(&handle);
        Ok(ok(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_file(self.real(&filename)?).await.map_err(io)?;
        Ok(ok(id))
    }

    async fn mkdir(&mut self, id: u32, path: String, _a: FileAttributes) -> Result<Status, Self::Error> {
        tokio::fs::create_dir(self.real(&path)?).await.map_err(io)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_dir(self.real(&path)?).await.map_err(io)?;
        Ok(ok(id))
    }

    async fn rename(&mut self, id: u32, old: String, new: String) -> Result<Status, Self::Error> {
        tokio::fs::rename(self.real(&old)?, self.real(&new)?).await.map_err(io)?;
        Ok(ok(id))
    }
}
