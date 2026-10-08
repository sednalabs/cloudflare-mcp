//! Create-only retention; toolkit independently verifies the reachable namespace and bytes.
use super::{AdapterError, content_error, digest};
use mcp_toolkit_private_artifact::{DescriptorBoundArtifact, PrivateArtifactPolicy};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::private_file_custody::{file_identity, private_directory, safe_root_ancestor};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) struct ContentCustody {
    root: PathBuf,
    directory: File,
}

impl ContentCustody {
    pub(super) fn open() -> Result<Self, AdapterError> {
        let root = crate::config::worker_content_root()
            .ok_or_else(|| content_error("workers.content_root_unconfigured"))?;
        if !root.is_absolute()
            || root == std::path::Path::new("/")
            || !root
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(content_error("workers.content_custody_invalid"));
        }
        let mut directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open("/")
            .map_err(|_| content_error("workers.content_custody_invalid"))?;
        let parts: Vec<_> = root.components().skip(1).collect();
        for (index, part) in parts.iter().enumerate() {
            let name = CString::new(part.as_os_str().as_bytes())
                .map_err(|_| content_error("workers.content_custody_invalid"))?;
            // SAFETY: valid held parent descriptor and NUL-terminated component; ownership is transferred once.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(content_error("workers.content_custody_invalid"));
            }
            directory = unsafe { File::from_raw_fd(fd) };
            let metadata = directory
                .metadata()
                .map_err(|_| content_error("workers.content_custody_invalid"))?;
            if !(if index + 1 == parts.len() {
                private_directory(&metadata)
            } else {
                safe_root_ancestor(&metadata)
            }) {
                return Err(content_error("workers.content_custody_invalid"));
            }
        }
        Ok(Self { root, directory })
    }

    pub(super) fn retain(&self, bytes: &[u8], max_bytes: usize) -> Result<String, AdapterError> {
        let failure = || content_error("workers.content_custody_unverified");
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failure())?
            .as_nanos();
        let name = format!(
            "worker-content-{stamp}-{}.bin",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let component = CString::new(name.as_bytes()).map_err(|_| failure())?;
        // SAFETY: held directory, fixed generated basename and create-only private mode.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(failure());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let proof = (|| {
            file.write_all(bytes).map_err(|_| failure())?;
            file.sync_all().map_err(|_| failure())?;
            self.directory.sync_all().map_err(|_| failure())?;
            let artifact = DescriptorBoundArtifact::open(
                &self.root,
                &self.root.join(&name),
                PrivateArtifactPolicy::new(max_bytes as u64).map_err(|_| failure())?,
            )
            .map_err(|_| failure())?;
            let read = artifact.read().map_err(|_| failure())?;
            if read.bytes() != bytes
                || read.proof().sha256_hex() != digest(bytes)
                || file_identity(&file.metadata().map_err(|_| failure())?)
                    != file_identity(
                        &std::fs::symlink_metadata(self.root.join(&name)).map_err(|_| failure())?,
                    )
            {
                return Err(failure());
            }
            Ok(name.clone())
        })();
        if proof.is_err() {
            // Remove only this invocation's create-only file through the held directory.
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), component.as_ptr(), 0);
            }
        }
        proof
    }
}
