//! Shared Unix custody primitives for private, descriptor-held local files.
//!
//! This module owns no provider calls and no lifecycle state. It extracts the
//! stable identity and private-node policy already used by D1 migration
//! custody, then applies it to one read-only SQL artifact.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

pub(crate) const MAX_TRUSTED_SQL_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl fmt::Display for PrivateFileCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivateFileCustodyError {}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use libc::{O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_RDONLY};
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ArtifactSnapshot {
        identity: UnixFileIdentity,
        length: u64,
        mode: u32,
        uid: u32,
        links: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    impl ArtifactSnapshot {
        fn from_metadata(metadata: &Metadata) -> Self {
            Self {
                identity: file_identity(metadata),
                length: metadata.len(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                links: metadata.nlink(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
    }

    struct HeldDirectory {
        name: OsString,
        file: File,
        identity: UnixFileIdentity,
    }

    pub(crate) struct TrustedSqlArtifact {
        root_path: PathBuf,
        root: File,
        root_identity: UnixFileIdentity,
        directories: Vec<HeldDirectory>,
        file_name: OsString,
        file: File,
        snapshot: ArtifactSnapshot,
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

    pub(crate) fn current_effective_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    pub(crate) fn file_identity(metadata: &Metadata) -> UnixFileIdentity {
        UnixFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn private_owner(uid: u32) -> bool {
        uid == current_effective_uid()
    }

    fn private_mode(mode: u32) -> bool {
        mode & 0o077 == 0
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
            && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0)
    }

    fn normal_absolute_path(path: &Path) -> bool {
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    }

    fn validate_root_and_ancestors(root: &Path) -> Result<Metadata, PrivateFileCustodyError> {
        if !normal_absolute_path(root) {
            return Err(PrivateFileCustodyError::RootPathInvalid);
        }
        let metadata =
            fs::symlink_metadata(root).map_err(|_| PrivateFileCustodyError::RootUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PrivateFileCustodyError::RootUnavailable);
        }
        if !private_owner(metadata.uid()) {
            return Err(PrivateFileCustodyError::RootOwnershipMismatch);
        }
        if !private_mode(metadata.mode()) {
            return Err(PrivateFileCustodyError::RootModeMismatch);
        }
        for ancestor in root.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor)
                .map_err(|_| PrivateFileCustodyError::UnsafeRootAncestor)?;
            if !safe_root_ancestor(&metadata) {
                return Err(PrivateFileCustodyError::UnsafeRootAncestor);
            }
        }
        Ok(metadata)
    }

    fn open_at(parent: &File, name: &OsStr, flags: i32) -> io::Result<File> {
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))?;
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0) };
        if descriptor < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }

    fn open_directory(parent: &File, name: &OsStr) -> io::Result<File> {
        open_at(
            parent,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
        )
    }

    fn open_regular(parent: &File, name: &OsStr) -> io::Result<File> {
        open_at(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    }

    fn classify_file_metadata(metadata: &Metadata) -> Result<(), PrivateFileCustodyError> {
        if metadata.file_type().is_symlink() {
            return Err(PrivateFileCustodyError::FinalSymlink);
        }
        if !metadata.is_file() {
            return Err(PrivateFileCustodyError::InputNotRegular);
        }
        if !private_owner(metadata.uid()) {
            return Err(PrivateFileCustodyError::InputOwnershipMismatch);
        }
        if !private_mode(metadata.mode()) {
            return Err(PrivateFileCustodyError::InputModeMismatch);
        }
        if metadata.nlink() != 1 {
            return Err(PrivateFileCustodyError::InputHardlinkAmbiguous);
        }
        if metadata.len() == 0 || metadata.len() > MAX_TRUSTED_SQL_ARTIFACT_BYTES {
            return Err(PrivateFileCustodyError::InputSizeInvalid);
        }
        Ok(())
    }

    fn read_exact_snapshot(
        file: &File,
        snapshot: ArtifactSnapshot,
    ) -> Result<Vec<u8>, PrivateFileCustodyError> {
        let before = file
            .metadata()
            .map_err(|_| PrivateFileCustodyError::InputReadFailed)?;
        classify_file_metadata(&before)?;
        let before = ArtifactSnapshot::from_metadata(&before);
        if before.identity != snapshot.identity {
            return Err(PrivateFileCustodyError::InputIdentityDrift);
        }
        if before.length < snapshot.length {
            return Err(PrivateFileCustodyError::InputTruncated);
        }
        if before.length > snapshot.length {
            return Err(PrivateFileCustodyError::InputGrew);
        }
        if before != snapshot {
            return Err(PrivateFileCustodyError::InputMetadataDrift);
        }
        let length = usize::try_from(snapshot.length)
            .map_err(|_| PrivateFileCustodyError::InputSizeInvalid)?;
        let mut bytes = vec![0_u8; length];
        let mut offset = 0_usize;
        while offset < length {
            let read = file
                .read_at(&mut bytes[offset..], offset as u64)
                .map_err(|_| PrivateFileCustodyError::InputReadFailed)?;
            if read == 0 {
                return Err(PrivateFileCustodyError::InputTruncated);
            }
            offset += read;
        }
        let mut sentinel = [0_u8; 1];
        if file
            .read_at(&mut sentinel, snapshot.length)
            .map_err(|_| PrivateFileCustodyError::InputReadFailed)?
            != 0
        {
            return Err(PrivateFileCustodyError::InputGrew);
        }
        let after = file
            .metadata()
            .map_err(|_| PrivateFileCustodyError::InputReadFailed)?;
        classify_file_metadata(&after)?;
        let after = ArtifactSnapshot::from_metadata(&after);
        if after.identity != snapshot.identity {
            return Err(PrivateFileCustodyError::InputIdentityDrift);
        }
        if after.length < snapshot.length {
            return Err(PrivateFileCustodyError::InputTruncated);
        }
        if after.length > snapshot.length {
            return Err(PrivateFileCustodyError::InputGrew);
        }
        if after != snapshot {
            return Err(PrivateFileCustodyError::InputMetadataDrift);
        }
        Ok(bytes)
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    impl TrustedSqlArtifact {
        pub(crate) fn open(
            root_path: &Path,
            input_path: &Path,
        ) -> Result<Self, PrivateFileCustodyError> {
            let root_metadata = validate_root_and_ancestors(root_path)?;
            if !normal_absolute_path(input_path) {
                return Err(PrivateFileCustodyError::InputPathInvalid);
            }
            let relative = input_path
                .strip_prefix(root_path)
                .map_err(|_| PrivateFileCustodyError::InputOutsideRoot)?;
            let components = relative
                .components()
                .map(|part| match part {
                    Component::Normal(value) => Ok(value.to_os_string()),
                    _ => Err(PrivateFileCustodyError::InputPathInvalid),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (file_name, directory_names) = components
                .split_last()
                .ok_or(PrivateFileCustodyError::InputPathInvalid)?;
            let root = OpenOptions::new()
                .read(true)
                .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                .open(root_path)
                .map_err(|_| PrivateFileCustodyError::RootUnavailable)?;
            let held_root = root
                .metadata()
                .map_err(|_| PrivateFileCustodyError::RootUnavailable)?;
            if !private_directory(&held_root)
                || file_identity(&held_root) != file_identity(&root_metadata)
            {
                return Err(PrivateFileCustodyError::RootUnavailable);
            }

            let mut directories = Vec::new();
            let mut parent = &root;
            for name in directory_names {
                let directory = open_directory(parent, name)
                    .map_err(|_| PrivateFileCustodyError::InputAncestorUnsafe)?;
                let metadata = directory
                    .metadata()
                    .map_err(|_| PrivateFileCustodyError::InputAncestorUnsafe)?;
                if !private_directory(&metadata) {
                    return Err(PrivateFileCustodyError::InputAncestorUnsafe);
                }
                directories.push(HeldDirectory {
                    name: name.clone(),
                    identity: file_identity(&metadata),
                    file: directory,
                });
                parent = &directories.last().expect("just pushed").file;
            }

            let file = match open_regular(parent, file_name) {
                Ok(file) => file,
                Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                    return Err(PrivateFileCustodyError::FinalSymlink);
                }
                Err(_) => return Err(PrivateFileCustodyError::InputUnavailable),
            };
            let metadata = file
                .metadata()
                .map_err(|_| PrivateFileCustodyError::InputUnavailable)?;
            classify_file_metadata(&metadata)?;
            let snapshot = ArtifactSnapshot::from_metadata(&metadata);
            let bytes = read_exact_snapshot(&file, snapshot)?;
            let proof = TrustedSqlArtifactProof {
                byte_count: snapshot.length,
                sha256: sha256(&bytes),
            };
            let artifact = Self {
                root_path: root_path.to_path_buf(),
                root,
                root_identity: file_identity(&root_metadata),
                directories,
                file_name: file_name.clone(),
                file,
                snapshot,
                proof,
            };
            artifact.revalidate_namespace()?;
            Ok(artifact)
        }

        pub(crate) fn proof(&self) -> TrustedSqlArtifactProof {
            self.proof
        }

        pub(crate) fn read_for_upload(
            &self,
        ) -> Result<(Vec<u8>, TrustedSqlArtifactProof), PrivateFileCustodyError> {
            self.revalidate_namespace()?;
            let bytes = read_exact_snapshot(&self.file, self.snapshot)?;
            if sha256(&bytes) != self.proof.sha256 {
                return Err(PrivateFileCustodyError::InputContentDrift);
            }
            self.revalidate_namespace()?;
            Ok((bytes, self.proof))
        }

        fn revalidate_namespace(&self) -> Result<(), PrivateFileCustodyError> {
            let root_metadata = validate_root_and_ancestors(&self.root_path)?;
            let held_root = self
                .root
                .metadata()
                .map_err(|_| PrivateFileCustodyError::RootUnavailable)?;
            if !private_directory(&held_root)
                || file_identity(&held_root) != self.root_identity
                || file_identity(&root_metadata) != self.root_identity
            {
                return Err(PrivateFileCustodyError::DescriptorPathDisagreement);
            }
            let mut parent = &self.root;
            for directory in &self.directories {
                let held = directory
                    .file
                    .metadata()
                    .map_err(|_| PrivateFileCustodyError::InputAncestorUnsafe)?;
                let named = open_directory(parent, &directory.name)
                    .map_err(|_| PrivateFileCustodyError::InputAncestorUnsafe)?;
                let named = named
                    .metadata()
                    .map_err(|_| PrivateFileCustodyError::InputAncestorUnsafe)?;
                if !private_directory(&held)
                    || !private_directory(&named)
                    || file_identity(&held) != directory.identity
                    || file_identity(&named) != directory.identity
                {
                    return Err(PrivateFileCustodyError::DescriptorPathDisagreement);
                }
                parent = &directory.file;
            }
            let held = self
                .file
                .metadata()
                .map_err(|_| PrivateFileCustodyError::InputUnavailable)?;
            classify_file_metadata(&held)?;
            let named = open_regular(parent, &self.file_name)
                .map_err(|_| PrivateFileCustodyError::DescriptorPathDisagreement)?;
            let named = named
                .metadata()
                .map_err(|_| PrivateFileCustodyError::DescriptorPathDisagreement)?;
            classify_file_metadata(&named)?;
            if file_identity(&held) != self.snapshot.identity
                || file_identity(&named) != self.snapshot.identity
            {
                return Err(PrivateFileCustodyError::DescriptorPathDisagreement);
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs::Permissions;
        use std::io::Write;
        use std::os::unix::fs::{PermissionsExt, symlink};
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
                    "cloudflare-mcp-private-artifact-{label}-{}-{nonce}",
                    std::process::id()
                ));
                let root = base.join("root");
                let nested = root.join("nested");
                fs::create_dir_all(&nested).expect("create fixture");
                fs::set_permissions(&base, Permissions::from_mode(0o700)).expect("private base");
                fs::set_permissions(&root, Permissions::from_mode(0o700)).expect("private root");
                fs::set_permissions(&nested, Permissions::from_mode(0o700))
                    .expect("private nested");
                let input = nested.join("candidate.sql");
                fs::write(&input, b"CREATE TABLE fixture(id INTEGER);\n").expect("write input");
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
        fn trusted_artifact_round_trip_is_descriptor_bound_and_content_hashed() {
            let fixture = Fixture::new("round-trip");
            let artifact = TrustedSqlArtifact::open(&fixture.root, &fixture.input)
                .expect("open trusted artifact");
            let (bytes, proof) = artifact.read_for_upload().expect("stable read");
            assert_eq!(bytes, b"CREATE TABLE fixture(id INTEGER);\n");
            assert_eq!(proof.byte_count, bytes.len() as u64);
            assert_eq!(proof.sha256, sha256(&bytes));
            let debug = format!("{artifact:?}");
            assert!(!debug.contains(fixture.input.to_string_lossy().as_ref()));
            assert!(!debug.contains("CREATE TABLE"));
        }

        #[test]
        fn final_symlink_unsafe_ancestors_modes_and_hardlinks_fail_closed() {
            let symlink_fixture = Fixture::new("final-symlink");
            fs::remove_file(&symlink_fixture.input).expect("remove input");
            symlink("/dev/null", &symlink_fixture.input).expect("symlink input");
            assert_eq!(
                TrustedSqlArtifact::open(&symlink_fixture.root, &symlink_fixture.input)
                    .expect_err("final symlink must fail"),
                PrivateFileCustodyError::FinalSymlink
            );

            let ancestor_fixture = Fixture::new("ancestor-mode");
            fs::set_permissions(&ancestor_fixture.base, Permissions::from_mode(0o777))
                .expect("unsafe ancestor");
            assert_eq!(
                TrustedSqlArtifact::open(&ancestor_fixture.root, &ancestor_fixture.input)
                    .expect_err("unsafe root ancestor must fail"),
                PrivateFileCustodyError::UnsafeRootAncestor
            );

            let symlink_ancestor_fixture = Fixture::new("symlink-ancestor");
            let real_nested = symlink_ancestor_fixture.root.join("nested-real");
            fs::rename(symlink_ancestor_fixture.root.join("nested"), &real_nested)
                .expect("move nested directory");
            symlink(&real_nested, symlink_ancestor_fixture.root.join("nested"))
                .expect("symlink nested directory");
            assert_eq!(
                TrustedSqlArtifact::open(
                    &symlink_ancestor_fixture.root,
                    &symlink_ancestor_fixture.input,
                )
                .expect_err("symlink ancestor must fail"),
                PrivateFileCustodyError::InputAncestorUnsafe
            );

            let root_mode_fixture = Fixture::new("root-mode");
            fs::set_permissions(&root_mode_fixture.root, Permissions::from_mode(0o750))
                .expect("unsafe root mode");
            assert_eq!(
                TrustedSqlArtifact::open(&root_mode_fixture.root, &root_mode_fixture.input)
                    .expect_err("root mode must fail"),
                PrivateFileCustodyError::RootModeMismatch
            );

            let mode_fixture = Fixture::new("input-mode");
            fs::set_permissions(&mode_fixture.input, Permissions::from_mode(0o640))
                .expect("unsafe input mode");
            assert_eq!(
                TrustedSqlArtifact::open(&mode_fixture.root, &mode_fixture.input)
                    .expect_err("input mode must fail"),
                PrivateFileCustodyError::InputModeMismatch
            );

            let hardlink_fixture = Fixture::new("hardlink");
            fs::hard_link(
                &hardlink_fixture.input,
                hardlink_fixture.root.join("alias.sql"),
            )
            .expect("create hardlink");
            assert_eq!(
                TrustedSqlArtifact::open(&hardlink_fixture.root, &hardlink_fixture.input)
                    .expect_err("hardlink ambiguity must fail"),
                PrivateFileCustodyError::InputHardlinkAmbiguous
            );
        }

        #[test]
        fn ownership_and_device_inode_policy_reject_mismatch() {
            assert!(!private_owner(current_effective_uid().wrapping_add(1)));
            let expected = UnixFileIdentity {
                device: 1,
                inode: 2,
            };
            assert_ne!(
                expected,
                UnixFileIdentity {
                    device: 2,
                    inode: 2,
                }
            );
            assert_ne!(
                expected,
                UnixFileIdentity {
                    device: 1,
                    inode: 3,
                }
            );
        }

        #[test]
        fn replacement_growth_truncation_and_content_drift_fail_closed() {
            let replacement = Fixture::new("replacement");
            let artifact = TrustedSqlArtifact::open(&replacement.root, &replacement.input)
                .expect("open artifact");
            let displaced = replacement.input.with_extension("old");
            fs::rename(&replacement.input, &displaced).expect("displace input");
            fs::write(&replacement.input, b"CREATE TABLE other(id INTEGER);\n")
                .expect("replacement input");
            fs::set_permissions(&replacement.input, Permissions::from_mode(0o600))
                .expect("private replacement");
            assert_eq!(
                artifact
                    .read_for_upload()
                    .expect_err("replacement must fail"),
                PrivateFileCustodyError::DescriptorPathDisagreement
            );

            let growth = Fixture::new("growth");
            let artifact =
                TrustedSqlArtifact::open(&growth.root, &growth.input).expect("open artifact");
            OpenOptions::new()
                .append(true)
                .open(&growth.input)
                .expect("open growth input")
                .write_all(b"-- growth\n")
                .expect("grow input");
            assert_eq!(
                artifact.read_for_upload().expect_err("growth must fail"),
                PrivateFileCustodyError::InputGrew
            );

            let truncation = Fixture::new("truncation");
            let artifact = TrustedSqlArtifact::open(&truncation.root, &truncation.input)
                .expect("open artifact");
            OpenOptions::new()
                .write(true)
                .open(&truncation.input)
                .expect("open truncation input")
                .set_len(4)
                .expect("truncate input");
            assert_eq!(
                artifact
                    .read_for_upload()
                    .expect_err("truncation must fail"),
                PrivateFileCustodyError::InputTruncated
            );

            let content = Fixture::new("content-drift");
            let artifact =
                TrustedSqlArtifact::open(&content.root, &content.input).expect("open artifact");
            let mut replacement = b"CREATE TABLE fixture(id INTEGER);\n".to_vec();
            replacement[13] ^= 1;
            assert_eq!(replacement.len(), artifact.proof().byte_count as usize);
            fs::write(&content.input, replacement).expect("replace equal-size content");
            assert!(matches!(
                artifact
                    .read_for_upload()
                    .expect_err("content drift must fail"),
                PrivateFileCustodyError::InputMetadataDrift
                    | PrivateFileCustodyError::InputContentDrift
            ));
        }

        #[test]
        fn descriptor_path_and_ancestor_substitution_fail_closed() {
            let fixture = Fixture::new("ancestor-substitution");
            let artifact =
                TrustedSqlArtifact::open(&fixture.root, &fixture.input).expect("open artifact");
            let nested = fixture.root.join("nested");
            let displaced = fixture.root.join("nested-old");
            fs::rename(&nested, &displaced).expect("displace nested directory");
            fs::create_dir(&nested).expect("replace nested directory");
            fs::set_permissions(&nested, Permissions::from_mode(0o700))
                .expect("private replacement directory");
            fs::write(&fixture.input, b"CREATE TABLE fixture(id INTEGER);\n")
                .expect("replacement input");
            fs::set_permissions(&fixture.input, Permissions::from_mode(0o600))
                .expect("private replacement input");
            assert_eq!(
                artifact
                    .read_for_upload()
                    .expect_err("ancestor substitution must fail"),
                PrivateFileCustodyError::DescriptorPathDisagreement
            );
        }

        #[test]
        fn error_and_debug_surfaces_do_not_leak_private_inputs() {
            let fixture = Fixture::new("leakage");
            fs::set_permissions(&fixture.input, Permissions::from_mode(0o644))
                .expect("unsafe input mode");
            let error = TrustedSqlArtifact::open(&fixture.root, &fixture.input)
                .expect_err("unsafe mode must fail");
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(fixture.input.to_string_lossy().as_ref()));
            assert!(!rendered.contains("CREATE TABLE"));
            assert_eq!(error.code(), "d1.artifact.mode_mismatch");
        }

        #[test]
        fn outside_root_empty_and_oversized_inputs_are_rejected() {
            let fixture = Fixture::new("path-shape");
            let outside = fixture.base.join("outside.sql");
            fs::write(&outside, b"SELECT 1;\n").expect("outside input");
            fs::set_permissions(&outside, Permissions::from_mode(0o600))
                .expect("private outside input");
            assert_eq!(
                TrustedSqlArtifact::open(&fixture.root, &outside)
                    .expect_err("outside root must fail"),
                PrivateFileCustodyError::InputOutsideRoot
            );

            let empty = Fixture::new("empty");
            fs::write(&empty.input, b"").expect("empty input");
            assert_eq!(
                TrustedSqlArtifact::open(&empty.root, &empty.input)
                    .expect_err("empty input must fail"),
                PrivateFileCustodyError::InputSizeInvalid
            );

            let oversized = Fixture::new("oversized");
            OpenOptions::new()
                .write(true)
                .open(&oversized.input)
                .expect("open oversized input")
                .set_len(MAX_TRUSTED_SQL_ARTIFACT_BYTES + 1)
                .expect("create sparse oversized input");
            assert_eq!(
                TrustedSqlArtifact::open(&oversized.root, &oversized.input)
                    .expect_err("oversized input must fail"),
                PrivateFileCustodyError::InputSizeInvalid
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{
    TrustedSqlArtifact, file_identity, private_directory, private_regular_file, safe_root_ancestor,
};

#[cfg(not(target_os = "linux"))]
pub(crate) struct TrustedSqlArtifact;

#[cfg(not(target_os = "linux"))]
impl TrustedSqlArtifact {
    pub(crate) fn open(
        _root_path: &Path,
        _input_path: &Path,
    ) -> Result<Self, PrivateFileCustodyError> {
        Err(PrivateFileCustodyError::PlatformUnsupported)
    }

    pub(crate) fn read_for_upload(
        &self,
    ) -> Result<(Vec<u8>, TrustedSqlArtifactProof), PrivateFileCustodyError> {
        Err(PrivateFileCustodyError::PlatformUnsupported)
    }
}
