//! Account-bound validation and no-redirect transport for D1 SQL uploads.
//!
//! This module deliberately owns no D1 import lifecycle, admission, retry, or
//! terminal state. A caller may construct a target only from an import-init
//! response whose account and database context exactly match the intended
//! operation.

use std::fmt;
use std::time::Duration;

use url::{Host, Url};

use crate::private_file_custody::{
    PrivateFileCustodyError, TrustedSqlArtifact, TrustedSqlArtifactProof,
};

#[derive(Clone, Copy)]
pub(crate) struct D1ImportUploadSource<'a> {
    pub(crate) account_id: &'a str,
    pub(crate) database_id: &'a str,
    pub(crate) upload_url: &'a str,
}

impl fmt::Debug for D1ImportUploadSource<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("D1ImportUploadSource")
            .field("scope_supplied", &true)
            .finish_non_exhaustive()
    }
}

pub(crate) struct BoundD1ImportUploadTarget {
    account_id: String,
    database_id: String,
    url: Url,
}

impl fmt::Debug for BoundD1ImportUploadTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundD1ImportUploadTarget")
            .field("scope_bound", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1ImportUploadTargetError {
    AccountIdInvalid,
    DatabaseIdInvalid,
    AccountContextMismatch,
    DatabaseContextMismatch,
    UrlInvalid,
    SchemeUntrusted,
    AuthorityAmbiguous,
    HostUntrusted,
    AccountHostMismatch,
    PresignQueryMissing,
}

impl D1ImportUploadTargetError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::AccountIdInvalid => "d1.upload.account_id_invalid",
            Self::DatabaseIdInvalid => "d1.upload.database_id_invalid",
            Self::AccountContextMismatch => "d1.upload.account_context_mismatch",
            Self::DatabaseContextMismatch => "d1.upload.database_context_mismatch",
            Self::UrlInvalid => "d1.upload.url_invalid",
            Self::SchemeUntrusted => "d1.upload.scheme_untrusted",
            Self::AuthorityAmbiguous => "d1.upload.authority_ambiguous",
            Self::HostUntrusted => "d1.upload.host_untrusted",
            Self::AccountHostMismatch => "d1.upload.account_host_mismatch",
            Self::PresignQueryMissing => "d1.upload.presign_query_missing",
        }
    }
}

impl fmt::Display for D1ImportUploadTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for D1ImportUploadTargetError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1ImportUploadError {
    ClientUnavailable,
    TargetScopeMismatch,
    Artifact(PrivateFileCustodyError),
    RequestBuildFailed,
    OutcomeAmbiguous,
    RedirectRefused,
    ProviderRejected(u16),
    EtagMissing,
}

impl D1ImportUploadError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ClientUnavailable => "d1.upload.client_unavailable",
            Self::TargetScopeMismatch => "d1.upload.target_scope_mismatch",
            Self::Artifact(error) => error.code(),
            Self::RequestBuildFailed => "d1.upload.request_build_failed",
            Self::OutcomeAmbiguous => "d1.upload.outcome_ambiguous",
            Self::RedirectRefused => "d1.upload.redirect_refused",
            Self::ProviderRejected(_) => "d1.upload.provider_rejected",
            Self::EtagMissing => "d1.upload.etag_missing",
        }
    }
}

impl fmt::Display for D1ImportUploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for D1ImportUploadError {}

impl From<PrivateFileCustodyError> for D1ImportUploadError {
    fn from(value: PrivateFileCustodyError) -> Self {
        Self::Artifact(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1ImportUploadReceipt {
    pub(crate) status: u16,
    pub(crate) artifact: TrustedSqlArtifactProof,
    pub(crate) etag: String,
}

pub(crate) struct D1ImportUploadTransport {
    http: reqwest::Client,
    user_agent: String,
}

impl D1ImportUploadTransport {
    pub(crate) fn new(timeout: Duration, user_agent: String) -> Result<Self, D1ImportUploadError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| D1ImportUploadError::ClientUnavailable)?;
        Ok(Self { http, user_agent })
    }

    pub(crate) async fn upload(
        &self,
        expected_account_id: &str,
        expected_database_id: &str,
        target: &BoundD1ImportUploadTarget,
        artifact: &TrustedSqlArtifact,
    ) -> Result<D1ImportUploadReceipt, D1ImportUploadError> {
        target.assert_scope(expected_account_id, expected_database_id)?;
        let (bytes, proof) = artifact.read_for_upload()?;
        let request = self
            .http
            .put(target.url.clone())
            .header(reqwest::header::USER_AGENT, self.user_agent.clone())
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .body(bytes)
            .build()
            .map_err(|_| D1ImportUploadError::RequestBuildFailed)?;
        let response = self
            .http
            .execute(request)
            .await
            .map_err(|_| D1ImportUploadError::OutcomeAmbiguous)?;
        let status = response.status();
        if status.is_redirection() {
            return Err(D1ImportUploadError::RedirectRefused);
        }
        if !status.is_success() {
            return Err(D1ImportUploadError::ProviderRejected(status.as_u16()));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim_matches('"').to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .ok_or(D1ImportUploadError::EtagMissing)?;
        Ok(D1ImportUploadReceipt {
            status: status.as_u16(),
            artifact: proof,
            etag,
        })
    }
}

impl BoundD1ImportUploadTarget {
    pub(crate) fn bind(
        expected_account_id: &str,
        expected_database_id: &str,
        source: D1ImportUploadSource<'_>,
    ) -> Result<Self, D1ImportUploadTargetError> {
        if !canonical_account_id(expected_account_id) {
            return Err(D1ImportUploadTargetError::AccountIdInvalid);
        }
        if !canonical_database_id(expected_database_id) {
            return Err(D1ImportUploadTargetError::DatabaseIdInvalid);
        }
        if source.account_id != expected_account_id {
            return Err(D1ImportUploadTargetError::AccountContextMismatch);
        }
        if source.database_id != expected_database_id {
            return Err(D1ImportUploadTargetError::DatabaseContextMismatch);
        }
        if !source.upload_url.is_ascii() {
            return Err(D1ImportUploadTargetError::UrlInvalid);
        }
        let url =
            Url::parse(source.upload_url).map_err(|_| D1ImportUploadTargetError::UrlInvalid)?;
        if url.scheme() != "https" {
            return Err(D1ImportUploadTargetError::SchemeUntrusted);
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(D1ImportUploadTargetError::AuthorityAmbiguous);
        }
        if url.query().is_none_or(str::is_empty) {
            return Err(D1ImportUploadTargetError::PresignQueryMissing);
        }
        let Host::Domain(host) = url.host().ok_or(D1ImportUploadTargetError::HostUntrusted)? else {
            return Err(D1ImportUploadTargetError::HostUntrusted);
        };
        let account_label = r2_account_label(host)?;
        if account_label != expected_account_id {
            return Err(D1ImportUploadTargetError::AccountHostMismatch);
        }
        Ok(Self {
            account_id: expected_account_id.to_string(),
            database_id: expected_database_id.to_string(),
            url,
        })
    }

    fn assert_scope(
        &self,
        expected_account_id: &str,
        expected_database_id: &str,
    ) -> Result<(), D1ImportUploadError> {
        if self.account_id != expected_account_id || self.database_id != expected_database_id {
            return Err(D1ImportUploadError::TargetScopeMismatch);
        }
        Ok(())
    }
}

fn canonical_account_id(value: &str) -> bool {
    value.len() == 32
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_database_id(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.as_bytes().iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-'
        } else {
            byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
        }
    })
}

fn r2_account_label(host: &str) -> Result<&str, D1ImportUploadTargetError> {
    if !host.is_ascii() || host.ends_with('.') {
        return Err(D1ImportUploadTargetError::HostUntrusted);
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || label.starts_with("xn--")
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err(D1ImportUploadTargetError::HostUntrusted);
    }
    if labels.len() < 4 || labels[labels.len() - 3..] != ["r2", "cloudflarestorage", "com"] {
        return Err(D1ImportUploadTargetError::HostUntrusted);
    }
    let prefix = &labels[..labels.len() - 3];
    match prefix {
        [account] if canonical_account_id(account) => Ok(account),
        [bucket, account] if valid_bucket_label(bucket) && canonical_account_id(account) => {
            Ok(account)
        }
        [account, jurisdiction]
            if canonical_account_id(account) && valid_r2_jurisdiction(jurisdiction) =>
        {
            Ok(account)
        }
        [bucket, account, jurisdiction]
            if valid_bucket_label(bucket)
                && canonical_account_id(account)
                && valid_r2_jurisdiction(jurisdiction) =>
        {
            Ok(account)
        }
        _ => Err(D1ImportUploadTargetError::HostUntrusted),
    }
}

fn valid_bucket_label(label: &str) -> bool {
    (3..=63).contains(&label.len())
        && label
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && label
            .bytes()
            .next_back()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_r2_jurisdiction(label: &str) -> bool {
    matches!(label, "eu" | "fedramp" | "us")
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;
    use std::fs::{self, Permissions};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ACCOUNT: &str = "0123456789abcdef0123456789abcdef"; // DevSkim: ignore DS173237 -- synthetic account fixture, not a credential
    const OTHER_ACCOUNT: &str = "1123456789abcdef0123456789abcdef"; // DevSkim: ignore DS173237 -- synthetic account fixture, not a credential
    const DATABASE: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const OTHER_DATABASE: &str = "11234567-89ab-cdef-0123-456789abcdef";

    fn source<'a>(account: &'a str, database: &'a str, url: &'a str) -> D1ImportUploadSource<'a> {
        D1ImportUploadSource {
            account_id: account,
            database_id: database,
            upload_url: url,
        }
    }

    fn target_for_test(url: Url) -> BoundD1ImportUploadTarget {
        BoundD1ImportUploadTarget {
            account_id: ACCOUNT.to_string(),
            database_id: DATABASE.to_string(),
            url,
        }
    }

    struct ArtifactFixture {
        base: PathBuf,
        root: PathBuf,
        input: PathBuf,
    }

    impl ArtifactFixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let base = PathBuf::from("/tmp").join(format!(
                "cloudflare-mcp-upload-transport-{}-{nonce}",
                std::process::id()
            ));
            let root = base.join("root");
            fs::create_dir_all(&root).expect("create fixture");
            fs::set_permissions(&base, Permissions::from_mode(0o700)).expect("private base");
            fs::set_permissions(&root, Permissions::from_mode(0o700)).expect("private root");
            let input = root.join("candidate.sql");
            fs::write(&input, b"SELECT 1;\n").expect("write fixture");
            fs::set_permissions(&input, Permissions::from_mode(0o600)).expect("private input");
            Self { base, root, input }
        }

        fn artifact(&self) -> TrustedSqlArtifact {
            TrustedSqlArtifact::open(&self.root, &self.input).expect("trusted artifact")
        }
    }

    impl Drop for ArtifactFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn exact_account_hosts_and_context_bind_successfully() {
        for url in [
            format!("https://{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://bucket.{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://{ACCOUNT}.us.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://bucket.{ACCOUNT}.eu.r2.cloudflarestorage.com/object?signature=x"),
        ] {
            let target =
                BoundD1ImportUploadTarget::bind(ACCOUNT, DATABASE, source(ACCOUNT, DATABASE, &url))
                    .expect("bind exact target");
            assert!(target.assert_scope(ACCOUNT, DATABASE).is_ok());
            assert_eq!(
                format!("{target:?}"),
                "BoundD1ImportUploadTarget { scope_bound: true, .. }"
            );
        }
    }

    #[test]
    fn wrong_account_database_and_hostile_or_encoded_hosts_fail_closed() {
        let valid = format!("https://{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x");
        assert_eq!(
            BoundD1ImportUploadTarget::bind(
                ACCOUNT,
                DATABASE,
                source(OTHER_ACCOUNT, DATABASE, &valid),
            )
            .expect_err("wrong source account"),
            D1ImportUploadTargetError::AccountContextMismatch
        );
        assert_eq!(
            BoundD1ImportUploadTarget::bind(
                ACCOUNT,
                DATABASE,
                source(ACCOUNT, OTHER_DATABASE, &valid),
            )
            .expect_err("wrong source database"),
            D1ImportUploadTargetError::DatabaseContextMismatch
        );
        assert_eq!(
            target_for_test(Url::parse(&valid).expect("valid fixture URL"))
                .assert_scope(ACCOUNT, OTHER_DATABASE)
                .expect_err("target must remain database-bound"),
            D1ImportUploadError::TargetScopeMismatch
        );
        let wrong_account =
            format!("https://bucket.{OTHER_ACCOUNT}.r2.cloudflarestorage.com/object?signature=x");
        assert_eq!(
            BoundD1ImportUploadTarget::bind(
                ACCOUNT,
                DATABASE,
                source(ACCOUNT, DATABASE, &wrong_account),
            )
            .expect_err("wrong account host"),
            D1ImportUploadTargetError::AccountHostMismatch
        );
        for (case_index, hostile) in [
            format!("https://{ACCOUNT}.r2.cloudflarestorage.com.evil.example/object?signature=x"),
            format!("https://evil.example/{ACCOUNT}?signature=x"),
            format!("https://{ACCOUNT}.r2.cloudflarestorage.com./object?signature=x"),
            format!("https://xn--evil.{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://extra.bucket.{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://ab.{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!(
                "https://{}.{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x",
                "a".repeat(64)
            ),
            format!("https://%30{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://\u{ff45}vil.{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://user@{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://{ACCOUNT}.r2.cloudflarestorage.com:444/object?signature=x"),
            format!("http://{ACCOUNT}.r2.cloudflarestorage.com/object?signature=x"),
            format!("https://{ACCOUNT}.r2.cloudflarestorage.com/object"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                BoundD1ImportUploadTarget::bind(
                    ACCOUNT,
                    DATABASE,
                    source(ACCOUNT, DATABASE, &hostile),
                )
                .is_err(),
                "hostile authority case {case_index} must fail"
            );
        }
    }

    #[test]
    fn target_and_error_debug_surfaces_do_not_leak_private_values() {
        let private_url = format!(
            "https://{OTHER_ACCOUNT}.r2.cloudflarestorage.com/private-object?signature=secret"
        );
        let error = BoundD1ImportUploadTarget::bind(
            ACCOUNT,
            DATABASE,
            source(ACCOUNT, DATABASE, &private_url),
        )
        .expect_err("wrong account host");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(ACCOUNT));
        assert!(!rendered.contains(OTHER_ACCOUNT));
        assert!(!rendered.contains(DATABASE));
        assert!(!rendered.contains("private-object"));
        assert!(!rendered.contains("secret"));

        let source = source(ACCOUNT, DATABASE, &private_url);
        let rendered = format!("{source:?}");
        assert!(!rendered.contains(ACCOUNT));
        assert!(!rendered.contains(DATABASE));
        assert!(!rendered.contains("private-object"));
        assert!(!rendered.contains("secret"));
    }

    fn read_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("request timeout");
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            let Some(split) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header_end = split + 4;
            let headers = String::from_utf8(bytes[..header_end].to_vec()).expect("headers");
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + length {
                return (headers, bytes[header_end..header_end + length].to_vec());
            }
        }
        panic!("incomplete request")
    }

    #[tokio::test]
    async fn upload_uses_exact_descriptor_bytes_and_returns_content_free_receipt() {
        let fixture = ArtifactFixture::new();
        let artifact = fixture.artifact();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upload fixture"); // DevSkim: ignore DS162092 -- loopback-only transport fixture
        let address = listener.local_addr().expect("fixture address");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_for_thread = captured.clone();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept upload");
            let (headers, body) = read_request(&mut stream);
            assert!(headers.starts_with("PUT /upload?signature=test HTTP/1.1"));
            assert!(!headers.to_ascii_lowercase().contains("authorization:"));
            *captured_for_thread.lock().expect("capture body") = body;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\netag: \"fixture-etag\"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            )
            .expect("write response");
        });
        let target = target_for_test(
            Url::parse(&format!("http://{address}/upload?signature=test")) // DevSkim: ignore DS137138 -- loopback-only transport fixture
                .expect("fixture URL"),
        );
        let transport =
            D1ImportUploadTransport::new(Duration::from_secs(2), "cloudflare-mcp-test".to_string())
                .expect("transport");
        let receipt = transport
            .upload(ACCOUNT, DATABASE, &target, &artifact)
            .await
            .expect("upload fixture");
        thread.join().expect("fixture thread");
        assert_eq!(
            captured.lock().expect("captured body").as_slice(),
            b"SELECT 1;\n"
        );
        assert_eq!(receipt.status, StatusCode::OK.as_u16());
        assert_eq!(receipt.etag, "fixture-etag");
        assert_eq!(receipt.artifact, artifact.proof());
        let rendered = format!("{receipt:?}");
        assert!(!rendered.contains(fixture.input.to_string_lossy().as_ref()));
        assert!(!rendered.contains("SELECT 1"));
    }

    #[tokio::test]
    async fn redirects_are_refused_without_following_the_location() {
        let fixture = ArtifactFixture::new();
        let artifact = fixture.artifact();
        let redirect = TcpListener::bind("127.0.0.1:0").expect("bind redirect fixture"); // DevSkim: ignore DS162092 -- loopback-only redirect fixture
        let redirect_address = redirect.local_addr().expect("redirect address");
        let forbidden = TcpListener::bind("127.0.0.1:0").expect("bind forbidden target"); // DevSkim: ignore DS162092 -- loopback-only no-follow witness
        forbidden
            .set_nonblocking(true)
            .expect("nonblocking no-follow witness");
        let forbidden_address = forbidden.local_addr().expect("forbidden address");
        let thread = thread::spawn(move || {
            let (mut stream, _) = redirect.accept().expect("accept redirect request");
            let _ = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nlocation: http://{forbidden_address}/must-not-follow\r\ncontent-length: 0\r\nconnection: close\r\n\r\n" // DevSkim: ignore DS137138 -- loopback-only no-follow witness
            )
            .expect("write redirect");
        });
        let target = target_for_test(
            Url::parse(&format!("http://{redirect_address}/upload?signature=test")) // DevSkim: ignore DS137138 -- loopback-only redirect fixture
                .expect("fixture URL"),
        );
        let transport =
            D1ImportUploadTransport::new(Duration::from_secs(2), "cloudflare-mcp-test".to_string())
                .expect("transport");
        assert_eq!(
            transport
                .upload(ACCOUNT, DATABASE, &target, &artifact)
                .await
                .expect_err("redirect must fail"),
            D1ImportUploadError::RedirectRefused
        );
        thread.join().expect("redirect thread");
        assert!(matches!(
            forbidden.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}
