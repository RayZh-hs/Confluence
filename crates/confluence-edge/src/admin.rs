//! Explicit local-only Unix administration. One bounded command per connection.
use confluence_core::{CoreErr, PublicKey, PublishGuard, ScopeInstance};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    fs::{self, DirBuilder},
    io,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinSet,
};

use crate::{TcpTarget, UdpTarget};

const MAX_COMMAND: usize = 1024;
const MAX_CLIENTS: usize = 16;
const ADMIN_TIMEOUT: Duration = Duration::from_secs(3);

pub struct AdminSocket {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}
impl AdminSocket {
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = std::path::absolute(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected a socket path"))?;
        let temp = private_directory(parent)?;
        let staged = temp.0.join("s");
        let result = (|| {
            // Stage in a 0700 directory. The final pathname becomes visible
            // only after the socket has 0600 permissions, without a global umask.
            let listener = UnixListener::bind(&staged)?;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
            let stamp = fs::symlink_metadata(&staged)?;
            fs::hard_link(&staged, &path)?;
            Ok(Self {
                listener,
                path,
                device: stamp.dev(),
                inode: stamp.ino(),
                uid: stamp.uid(),
            })
        })();
        let _ = fs::remove_file(staged);
        result
    }

    /// Commands are publish-stream, publish-datagram, unpublish, revoke-peer
    /// and list. Publication guards live for the duration of this service.
    pub async fn serve(self, scope: ScopeInstance) -> io::Result<()> {
        let state = Arc::new(AdminState {
            scope,
            publications: Default::default(),
        });
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                _ = clients.join_next(), if !clients.is_empty() => {},
                accepted = self.listener.accept(), if clients.len() < MAX_CLIENTS => {
                    let (stream, _) = accepted?;
                    if stream.peer_cred()?.uid() == self.uid {
                        let state = state.clone();
                        clients.spawn(async move { let _ = tokio::time::timeout(ADMIN_TIMEOUT, command(stream, state)).await; });
                    }
                }
            }
        }
    }
}
impl Drop for AdminSocket {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|path| {
            path.file_type().is_socket() && path.dev() == self.device && path.ino() == self.inode
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct PrivateDirectory(PathBuf);
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}
fn private_directory(parent: &Path) -> io::Result<PrivateDirectory> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..32 {
        let name = format!(
            ".cf-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = parent.join(name);
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(PrivateDirectory(path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to stage Unix socket",
    ))
}

struct AdminState {
    scope: ScopeInstance,
    publications: Mutex<HashMap<String, PublishGuard>>,
}
async fn command(mut stream: UnixStream, state: Arc<AdminState>) -> io::Result<()> {
    let mut request = Vec::with_capacity(128);
    let mut chunk = [0u8; 256];
    while request.len() < MAX_COMMAND {
        let limit = (MAX_COMMAND - request.len()).min(chunk.len());
        let n = stream.read(&mut chunk[..limit]).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if let Some(pos) = chunk[..n].iter().position(|&b| b == b'\n') {
            request.extend_from_slice(&chunk[..pos]);
            let response = std::str::from_utf8(&request)
                .map_err(|_| CoreErr::Malformed)
                .and_then(|input| state.execute(input));
            let response = match response {
                Ok(payload) => format!("OK{payload}\n"),
                Err(error) => format!("ERR {error}\n"),
            };
            stream.write_all(response.as_bytes()).await?;
            return stream.shutdown().await;
        }
        request.extend_from_slice(&chunk[..n]);
    }
    stream.write_all(b"ERR command too long\n").await
}
impl AdminState {
    fn execute(&self, input: &str) -> Result<String, CoreErr> {
        let fields: Vec<_> = input.split_ascii_whitespace().collect();
        let mut publications = self.publications.lock();
        match fields.as_slice() {
            ["publish-stream", name, address] => {
                let target = Arc::new(TcpTarget(addr(address)?));
                let guard = self.scope.publish_stream(name, target)?;
                publications.insert((*name).into(), guard);
            }
            ["publish-datagram", name, mtu, address] => {
                let min = mtu.parse().map_err(|_| CoreErr::Malformed)?;
                let guard =
                    self.scope
                        .publish_datagram(name, min, Arc::new(UdpTarget(addr(address)?)))?;
                publications.insert((*name).into(), guard);
            }
            ["unpublish", name] => {
                drop(publications.remove(*name).ok_or(CoreErr::Unpublished)?);
            }
            ["revoke-peer", key] => self.scope.revoke_peer(&peer(key)?),
            ["list"] => {
                let mut names: Vec<_> = publications.keys().map(String::as_str).collect();
                names.sort_unstable();
                return Ok(names.into_iter().fold(String::new(), |mut list, name| {
                    list.push(' ');
                    list.push_str(name);
                    list
                }));
            }
            _ => return Err(CoreErr::Malformed),
        }
        Ok(String::new())
    }
}
fn addr(input: &str) -> Result<SocketAddr, CoreErr> {
    input.parse().map_err(|_| CoreErr::Malformed)
}
fn peer(input: &str) -> Result<PublicKey, CoreErr> {
    if input.len() != 64 || !input.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(CoreErr::Malformed);
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
            .map_err(|_| CoreErr::Malformed)?;
    }
    Ok(PublicKey(bytes))
}
