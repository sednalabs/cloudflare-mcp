//! Descriptor-bound local custody for D1 row-write artifacts.
//!
//! The toolkit owns no-follow path traversal, private ownership/mode checks,
//! descriptor retention, and exact revalidation. This adapter adds only a
//! narrow create-once helper for a direct child of an already private root.
//! Opening an existing artifact never creates or repairs it: custody loss is
//! reconciliation evidence, not permission to start fresh.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use mcp_toolkit_private_artifact::{
    ArtifactProof, DescriptorBoundArtifact, PrivateArtifactError, PrivateArtifactPolicy,
};
use sha2::Digest;

use crate::private_file_custody::{file_identity, private_directory};

const MAX_D1_CUSTODY_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1CustodyDescriptorError {
    InvalidPolicy,
    CreateFailed,
    RootAndInputMustBeAbsolute,
    InputMustBeDirectChild,
    Toolkit(PrivateArtifactError),
}

/// Holds the toolkit's descriptor-bound artifact and its admission proof.
pub(crate) struct D1CustodyDescriptor {
    held: DescriptorBoundArtifact,
    proof: ArtifactProof,
}

impl std::fmt::Debug for D1CustodyDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("D1CustodyDescriptor")
            .field("byte_count", &self.proof.byte_count())
            .field("sha256", &self.proof.sha256_hex())
            .finish_non_exhaustive()
    }
}

impl D1CustodyDescriptor {
    /// Open one existing exact artifact. This function has no create fallback.
    pub(crate) fn open_existing(
        root: &Path,
        input: &Path,
    ) -> Result<Self, D1CustodyDescriptorError> {
        let policy = PrivateArtifactPolicy::new(MAX_D1_CUSTODY_ARTIFACT_BYTES)
            .map_err(|_| D1CustodyDescriptorError::InvalidPolicy)?;
        let held = DescriptorBoundArtifact::open(root, input, policy)
            .map_err(D1CustodyDescriptorError::Toolkit)?;
        Ok(Self {
            proof: held.proof(),
            held,
        })
    }

    /// Create one direct child exactly once, then retain a descriptor-bound
    /// handle for all later reads. Existing paths are never replaced.
    pub(crate) fn create_once(
        root: &Path,
        input: &Path,
        bytes: &[u8],
    ) -> Result<Self, D1CustodyDescriptorError> {
        if !root.is_absolute() || !input.is_absolute() {
            return Err(D1CustodyDescriptorError::RootAndInputMustBeAbsolute);
        }
        if input.parent() != Some(root) {
            return Err(D1CustodyDescriptorError::InputMustBeDirectChild);
        }
        if bytes.len() as u64 > MAX_D1_CUSTODY_ARTIFACT_BYTES {
            return Err(D1CustodyDescriptorError::InvalidPolicy);
        }
        // Parent creation is explicitly operator-owned; this helper never
        // creates or repairs a root, and refuses a root symlink.
        let root_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)
            .map_err(|_| D1CustodyDescriptorError::CreateFailed)?;
        let metadata = root_file
            .metadata()
            .map_err(|_| D1CustodyDescriptorError::CreateFailed)?;
        if !private_directory(&metadata) {
            return Err(D1CustodyDescriptorError::CreateFailed);
        }
        let root_identity = file_identity(&metadata);
        let name = input
            .file_name()
            .filter(|name| !name.as_bytes().is_empty())
            .ok_or(D1CustodyDescriptorError::InputMustBeDirectChild)?;
        let name = CString::new(name.as_bytes())
            .map_err(|_| D1CustodyDescriptorError::InputMustBeDirectChild)?;
        // Create relative to the held root descriptor.  This closes the
        // root-path replacement race between the private-directory check and
        // the one-time file installation.
        let raw_fd = unsafe {
            libc::openat(
                root_file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw_fd < 0 {
            return Err(D1CustodyDescriptorError::CreateFailed);
        }
        // SAFETY: openat returned a new owned descriptor on success.
        let mut file = unsafe { File::from_raw_fd(raw_fd) };
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| D1CustodyDescriptorError::CreateFailed)?;
        let created_identity = file_identity(
            &file
                .metadata()
                .map_err(|_| D1CustodyDescriptorError::CreateFailed)?,
        );
        drop(file);
        let current_root =
            std::fs::symlink_metadata(root).map_err(|_| D1CustodyDescriptorError::CreateFailed)?;
        if !private_directory(&current_root) || file_identity(&current_root) != root_identity {
            return Err(D1CustodyDescriptorError::CreateFailed);
        }
        let descriptor = Self::open_existing(root, input)?;
        let current_input =
            std::fs::symlink_metadata(input).map_err(|_| D1CustodyDescriptorError::CreateFailed)?;
        if !current_input.is_file()
            || current_input.file_type().is_symlink()
            || file_identity(&current_input) != created_identity
        {
            return Err(D1CustodyDescriptorError::CreateFailed);
        }
        if descriptor.proof.byte_count() != bytes.len() as u64
            || descriptor.proof.sha256() != <[u8; 32]>::from(sha2::Sha256::digest(bytes))
        {
            return Err(D1CustodyDescriptorError::CreateFailed);
        }
        Ok(descriptor)
    }

    pub(crate) fn proof(&self) -> ArtifactProof {
        self.proof
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, D1CustodyDescriptorError> {
        self.held
            .read()
            .map(|read| read.into_bytes())
            .map_err(D1CustodyDescriptorError::Toolkit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        base: PathBuf,
        root: PathBuf,
        input: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let base = PathBuf::from("/tmp").join(format!(
                "cloudflare-mcp-d1-custody-{label}-{}-{nonce}",
                std::process::id()
            ));
            let root = base.join("root");
            fs::create_dir_all(&root).expect("create fixture");
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("private base");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
            Self {
                input: root.join("artifact.json"),
                base,
                root,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn create_once_then_read_preserves_descriptor_bound_proof() {
        let fixture = Fixture::new("round-trip");
        let bytes = b"{\"version\":1}\n";
        let descriptor = D1CustodyDescriptor::create_once(&fixture.root, &fixture.input, bytes)
            .expect("create exact artifact");
        assert_eq!(descriptor.read().expect("read held artifact"), bytes);
        assert_eq!(descriptor.proof().byte_count(), bytes.len() as u64);
        assert_eq!(
            descriptor.proof().sha256(),
            <[u8; 32]>::from(sha2::Sha256::digest(bytes))
        );
        assert!(matches!(
            D1CustodyDescriptor::create_once(&fixture.root, &fixture.input, b"other"),
            Err(D1CustodyDescriptorError::CreateFailed)
        ));
    }

    #[test]
    fn custody_loss_never_falls_back_to_fresh_creation() {
        let fixture = Fixture::new("loss");
        let bytes = b"stable\n";
        let descriptor = D1CustodyDescriptor::create_once(&fixture.root, &fixture.input, bytes)
            .expect("create exact artifact");
        fs::remove_file(&fixture.input).expect("remove artifact to model custody loss");
        assert!(matches!(
            descriptor.read(),
            Err(D1CustodyDescriptorError::Toolkit(_))
        ));
        assert!(matches!(
            D1CustodyDescriptor::open_existing(&fixture.root, &fixture.input),
            Err(D1CustodyDescriptorError::Toolkit(_))
        ));
    }
}
