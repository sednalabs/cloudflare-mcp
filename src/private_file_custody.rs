//! Cloudflare-specific adapter over the toolkit's private-artifact custody.
//!
//! The toolkit owns descriptor-bound reads, namespace revalidation, and the
//! generic path-free failure taxonomy. This module retains only the D1 upload
//! contract: non-empty SQL artifacts, legacy aggregate error codes, and the
//! small Unix metadata predicates shared with migration-lease custody.

use std::fmt;
use std::path::Path;

use mcp_toolkit_private_artifact::{
    ArtifactProof, DescriptorBoundArtifact, PrivateArtifactError, PrivateArtifactPolicy,
};

pub(crate) const MAX_TRUSTED_SQL_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) struct UnixFileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustedSqlArtifactProof {
    pub(crate) byte_count: u64,
    pub(crate) sha256: [u8; 32],
}

impl TrustedSqlArtifactProof {
    pub(crate) fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

impl From<ArtifactProof> for TrustedSqlArtifactProof {
    fn from(value: ArtifactProof) -> Self {
        Self {
            byte_count: value.byte_count(),
            sha256: value.sha256(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateFileCustodyError {
    PlatformUnsupported,
    RootPathInvalid,
    RootUnavailable,
    RootOwnershipMismatch,
    RootModeMismatch,
    UnsafeRootAncestor,
    InputPathInvalid,
    InputOutsideRoot,
    InputAncestorUnsafe,
    InputUnavailable,
    FinalSymlink,
    InputNotRegular,
    InputOwnershipMismatch,
    InputModeMismatch,
    InputHardlinkAmbiguous,
    InputSizeInvalid,
    InputReadFailed,
    InputTruncated,
    InputGrew,
    InputIdentityDrift,
    InputMetadataDrift,
    DescriptorPathDisagreement,
    InputContentDrift,
}

impl PrivateFileCustodyError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::PlatformUnsupported => "d1.artifact.platform_unsupported",
            Self::RootPathInvalid => "d1.artifact.root_path_invalid",
            Self::RootUnavailable => "d1.artifact.root_unavailable",
            Self::RootOwnershipMismatch => "d1.artifact.root_owner_mismatch",
            Self::RootModeMismatch => "d1.artifact.root_mode_mismatch",
            Self::UnsafeRootAncestor => "d1.artifact.root_ancestor_unsafe",
            Self::InputPathInvalid => "d1.artifact.path_invalid",
            Self::InputOutsideRoot => "d1.artifact.outside_root",
            Self::InputAncestorUnsafe => "d1.artifact.ancestor_unsafe",
            Self::InputUnavailable => "d1.artifact.unavailable",
            Self::FinalSymlink => "d1.artifact.final_symlink",
            Self::InputNotRegular => "d1.artifact.not_regular",
            Self::InputOwnershipMismatch => "d1.artifact.owner_mismatch",
            Self::InputModeMismatch => "d1.artifact.mode_mismatch",
            Self::InputHardlinkAmbiguous => "d1.artifact.hardlink_ambiguous",
            Self::InputSizeInvalid => "d1.artifact.size_invalid",
            Self::InputReadFailed => "d1.artifact.read_failed",
            Self::InputTruncated => "d1.artifact.truncated",
            Self::InputGrew => "d1.artifact.grew",
            Self::InputIdentityDrift => "d1.artifact.identity_drift",
            Self::InputMetadataDrift => "d1.artifact.metadata_drift",
            Self::DescriptorPathDisagreement => "d1.artifact.path_disagreement",
            Self::InputContentDrift => "d1.artifact.content_drift",
        }
    }
}

impl From<PrivateArtifactError> for PrivateFileCustodyError {
    fn from(value: PrivateArtifactError) -> Self {
        match value {
            PrivateArtifactError::PlatformUnsupported => Self::PlatformUnsupported,
            PrivateArtifactError::InvalidSizeLimit => Self::InputSizeInvalid,
            PrivateArtifactError::RootPathInvalid => Self::RootPathInvalid,
            PrivateArtifactError::RootUnavailable => Self::RootUnavailable,
            PrivateArtifactError::RootOwnershipMismatch => Self::RootOwnershipMismatch,
            PrivateArtifactError::RootModeMismatch => Self::RootModeMismatch,
            PrivateArtifactError::UnsafeRootAncestor => Self::UnsafeRootAncestor,
            PrivateArtifactError::InputPathInvalid => Self::InputPathInvalid,
            PrivateArtifactError::InputOutsideRoot => Self::InputOutsideRoot,
            PrivateArtifactError::InputAncestorUnsafe => Self::InputAncestorUnsafe,
            PrivateArtifactError::InputUnavailable => Self::InputUnavailable,
            PrivateArtifactError::FinalSymlink => Self::FinalSymlink,
            PrivateArtifactError::InputNotRegular => Self::InputNotRegular,
            PrivateArtifactError::InputOwnershipMismatch => Self::InputOwnershipMismatch,
            PrivateArtifactError::InputModeMismatch => Self::InputModeMismatch,
            PrivateArtifactError::InputHardlinkAmbiguous => Self::InputHardlinkAmbiguous,
            PrivateArtifactError::InputSizeInvalid => Self::InputSizeInvalid,
            PrivateArtifactError::InputReadFailed => Self::InputReadFailed,
            PrivateArtifactError::InputTruncated => Self::InputTruncated,
            PrivateArtifactError::InputGrew => Self::InputGrew,
            PrivateArtifactError::InputIdentityDrift => Self::InputIdentityDrift,
            PrivateArtifactError::InputMetadataDrift => Self::InputMetadataDrift,
            PrivateArtifactError::DescriptorPathDisagreement => Self::DescriptorPathDisagreement,
            PrivateArtifactError::InputContentDrift => Self::InputContentDrift,
        }
    }
}

impl fmt::Display for PrivateFileCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivateFileCustodyError {}

pub(crate) struct TrustedSqlArtifact {
    inner: DescriptorBoundArtifact,
    proof: TrustedSqlArtifactProof,
}

impl fmt::Debug for TrustedSqlArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedSqlArtifact")
            .field("byte_count", &self.proof.byte_count)
            .field("sha256", &self.proof.sha256_hex())
            .finish_non_exhaustive()
    }
}

impl TrustedSqlArtifact {
    pub(crate) fn open(
        root_path: &Path,
        input_path: &Path,
    ) -> Result<Self, PrivateFileCustodyError> {
        let policy = PrivateArtifactPolicy::new(MAX_TRUSTED_SQL_ARTIFACT_BYTES)
            .map_err(PrivateFileCustodyError::from)?;
        let inner = DescriptorBoundArtifact::open(root_path, input_path, policy)
            .map_err(PrivateFileCustodyError::from)?;
        let proof = TrustedSqlArtifactProof::from(inner.proof());
        if proof.byte_count == 0 {
            return Err(PrivateFileCustodyError::InputSizeInvalid);
        }
        Ok(Self { inner, proof })
    }

    pub(crate) fn proof(&self) -> TrustedSqlArtifactProof {
        self.proof
    }

    pub(crate) fn read_for_upload(
        &self,
    ) -> Result<(Vec<u8>, TrustedSqlArtifactProof), PrivateFileCustodyError> {
        let read = self.inner.read().map_err(PrivateFileCustodyError::from)?;
        let proof = TrustedSqlArtifactProof::from(read.proof());
        if proof != self.proof {
            return Err(PrivateFileCustodyError::InputContentDrift);
        }
        Ok((read.into_bytes(), proof))
    }
}

#[cfg(target_os = "linux")]
mod linux_metadata {
    use super::UnixFileIdentity;
    use std::fs::Metadata;
    use std::os::unix::fs::MetadataExt;

    fn current_effective_uid() -> u32 {
        // SAFETY: geteuid has no arguments and no memory-safety preconditions.
        unsafe { libc::geteuid() }
    }

    fn private_owner(uid: u32) -> bool {
        uid == current_effective_uid()
    }

    fn trusted_ancestor_owner(uid: u32) -> bool {
        uid == 0 || private_owner(uid)
    }

    fn private_mode(mode: u32) -> bool {
        mode & 0o077 == 0
    }

    pub(crate) fn file_identity(metadata: &Metadata) -> UnixFileIdentity {
        UnixFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    pub(crate) fn private_regular_file(metadata: &Metadata) -> bool {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && private_owner(metadata.uid())
            && private_mode(metadata.mode())
    }

    pub(crate) fn private_directory(metadata: &Metadata) -> bool {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && private_owner(metadata.uid())
            && private_mode(metadata.mode())
    }

    pub(crate) fn safe_root_ancestor(metadata: &Metadata) -> bool {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && trusted_ancestor_owner(metadata.uid())
            && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0)
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux_metadata::{
    file_identity, private_directory, private_regular_file, safe_root_ancestor,
};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        base: PathBuf,
        root: PathBuf,
        input: PathBuf,
    }

    impl Fixture {
        fn new(label: &str, bytes: &[u8]) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let base = PathBuf::from("/tmp").join(format!(
                "cloudflare-mcp-toolkit-artifact-{label}-{}-{nonce}",
                std::process::id()
            ));
            let root = base.join("root");
            fs::create_dir_all(&root).expect("create fixture");
            fs::set_permissions(&base, Permissions::from_mode(0o700)).expect("private base");
            fs::set_permissions(&root, Permissions::from_mode(0o700)).expect("private root");
            let input = root.join("candidate.sql");
            fs::write(&input, bytes).expect("write input");
            fs::set_permissions(&input, Permissions::from_mode(0o600)).expect("private input");
            Self { base, root, input }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn trusted_sql_artifact_preserves_upload_proof_and_private_debug() {
        let bytes = b"CREATE TABLE fixture(id INTEGER);\n";
        let fixture = Fixture::new("round-trip", bytes);
        let artifact = TrustedSqlArtifact::open(&fixture.root, &fixture.input)
            .expect("open trusted SQL artifact");
        let (read, proof) = artifact.read_for_upload().expect("read stable artifact");
        assert_eq!(read, bytes);
        assert_eq!(proof, artifact.proof());
        assert_eq!(proof.byte_count, bytes.len() as u64);
        assert_eq!(proof.sha256, <[u8; 32]>::from(Sha256::digest(bytes)));
        let debug = format!("{artifact:?}");
        assert!(!debug.contains(fixture.input.to_string_lossy().as_ref()));
        assert!(!debug.contains("CREATE TABLE"));
    }

    #[test]
    fn empty_sql_artifact_retains_existing_fail_closed_contract() {
        let fixture = Fixture::new("empty", b"");
        assert_eq!(
            TrustedSqlArtifact::open(&fixture.root, &fixture.input)
                .expect_err("empty SQL artifact must fail"),
            PrivateFileCustodyError::InputSizeInvalid
        );
    }

    #[test]
    fn toolkit_error_codes_map_to_existing_d1_error_codes() {
        assert_eq!(
            PrivateFileCustodyError::from(PrivateArtifactError::FinalSymlink).code(),
            "d1.artifact.final_symlink"
        );
        assert_eq!(
            PrivateFileCustodyError::from(PrivateArtifactError::InputContentDrift).code(),
            "d1.artifact.content_drift"
        );
        assert_eq!(
            PrivateFileCustodyError::from(PrivateArtifactError::InvalidSizeLimit).code(),
            "d1.artifact.size_invalid"
        );
    }
}
