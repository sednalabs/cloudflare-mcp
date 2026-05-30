use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

pub(crate) const MAX_PAGES_ASSET_COUNT_DEFAULT: usize = 20_000;
pub(crate) const MAX_PAGES_ASSET_BYTES: u64 = 25 * 1024 * 1024;
const MAX_UPLOAD_BUCKET_BYTES: u64 = 40 * 1024 * 1024;
const MAX_UPLOAD_BUCKET_FILE_COUNT: usize = 2_000;

#[derive(Debug, Clone)]
pub(crate) struct PagesAssetFile {
    pub(crate) relative_path: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) content_type: String,
    pub(crate) size_bytes: u64,
    pub(crate) hash: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PagesSpecialFile {
    pub(crate) form_name: &'static str,
    pub(crate) file_name: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) size_bytes: u64,
}

impl PagesSpecialFile {
    pub(crate) fn read_bytes(&self) -> Result<Vec<u8>, PagesDirectoryError> {
        fs::read(&self.path).map_err(|err| {
            PagesDirectoryError::new(
                "pages.directory_read_failed",
                format!("failed reading {}: {err}", self.file_name),
                "Check the Pages deployment directory permissions and retry.",
            )
        })
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PagesSpecialFiles {
    pub(crate) headers: Option<PagesSpecialFile>,
    pub(crate) redirects: Option<PagesSpecialFile>,
    pub(crate) routes: Option<PagesSpecialFile>,
    pub(crate) worker: Option<PagesSpecialFile>,
    pub(crate) worker_bundle: Option<PagesSpecialFile>,
    pub(crate) functions_filepath_routing_config: Option<PagesSpecialFile>,
}

impl PagesSpecialFiles {
    fn summary(&self) -> PagesSpecialFilesSummary {
        PagesSpecialFilesSummary {
            headers: self.headers.as_ref().map(special_file_summary),
            redirects: self.redirects.as_ref().map(special_file_summary),
            routes: self.routes.as_ref().map(special_file_summary),
            worker: self.worker.as_ref().map(special_file_summary),
            worker_bundle: self.worker_bundle.as_ref().map(special_file_summary),
            functions_filepath_routing_config: self
                .functions_filepath_routing_config
                .as_ref()
                .map(special_file_summary),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PagesDirectoryPackage {
    pub(crate) root_name: String,
    pub(crate) assets: Vec<PagesAssetFile>,
    pub(crate) total_asset_bytes: u64,
    pub(crate) special_files: PagesSpecialFiles,
    pub(crate) functions: PagesFunctionsSummary,
    pub(crate) manifest: BTreeMap<String, String>,
    pub(crate) manifest_sha256: String,
    temporary_directories: Vec<PathBuf>,
}

impl PagesDirectoryPackage {
    pub(crate) fn summary(&self) -> PagesDirectorySummary {
        PagesDirectorySummary {
            root_name: self.root_name.clone(),
            asset_count: self.assets.len(),
            total_asset_bytes: self.total_asset_bytes,
            manifest_sha256: self.manifest_sha256.clone(),
            special_files: self.special_files.summary(),
            functions: self.functions.clone(),
        }
    }

    pub(crate) fn hashes(&self) -> Vec<String> {
        self.assets.iter().map(|asset| asset.hash.clone()).collect()
    }

    pub(crate) fn assets_for_hashes(&self, hashes: &[String]) -> Vec<PagesAssetFile> {
        let requested = hashes.iter().cloned().collect::<HashSet<_>>();
        let mut assets = self
            .assets
            .iter()
            .filter(|asset| requested.contains(&asset.hash))
            .cloned()
            .collect::<Vec<_>>();
        assets.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        assets
    }
}

impl Drop for PagesDirectoryPackage {
    fn drop(&mut self) {
        for path in &self.temporary_directories {
            let _ = fs::remove_dir_all(path);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PagesDirectorySummary {
    pub(crate) root_name: String,
    pub(crate) asset_count: usize,
    pub(crate) total_asset_bytes: u64,
    pub(crate) manifest_sha256: String,
    pub(crate) special_files: PagesSpecialFilesSummary,
    pub(crate) functions: PagesFunctionsSummary,
}

#[derive(Debug, Clone, Serialize, Default)]
pub(crate) struct PagesSpecialFilesSummary {
    pub(crate) headers: Option<PagesSpecialFileSummary>,
    pub(crate) redirects: Option<PagesSpecialFileSummary>,
    pub(crate) routes: Option<PagesSpecialFileSummary>,
    pub(crate) worker: Option<PagesSpecialFileSummary>,
    pub(crate) worker_bundle: Option<PagesSpecialFileSummary>,
    pub(crate) functions_filepath_routing_config: Option<PagesSpecialFileSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PagesSpecialFileSummary {
    pub(crate) name: &'static str,
    pub(crate) size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub(crate) struct PagesFunctionsSummary {
    pub(crate) detected: bool,
    pub(crate) included: bool,
    pub(crate) project_root: Option<String>,
    pub(crate) functions_directory: Option<String>,
    pub(crate) wrangler_command: Option<String>,
    pub(crate) worker_bundle: Option<PagesSpecialFileSummary>,
    pub(crate) generated_routes: Option<PagesSpecialFileSummary>,
    pub(crate) filepath_routing_config: Option<PagesSpecialFileSummary>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PagesDirectoryInspectOptions {
    pub(crate) project_root: Option<String>,
    pub(crate) wrangler_bin: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct PagesDirectoryError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) hint: &'static str,
}

impl PagesDirectoryError {
    fn new(code: &'static str, message: impl Into<String>, hint: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            hint,
        }
    }

    pub(crate) fn payload(&self) -> serde_json::Value {
        json!({
            "code": self.code,
            "message": self.message,
            "hint": self.hint,
        })
    }
}

#[cfg(test)]
fn inspect_pages_directory(
    directory: &str,
    max_files: usize,
) -> Result<PagesDirectoryPackage, PagesDirectoryError> {
    inspect_pages_directory_with_options(
        directory,
        max_files,
        PagesDirectoryInspectOptions::default(),
    )
}

pub(crate) fn inspect_pages_directory_with_options(
    directory: &str,
    max_files: usize,
    options: PagesDirectoryInspectOptions,
) -> Result<PagesDirectoryPackage, PagesDirectoryError> {
    let directory = directory.trim();
    if directory.is_empty() {
        return Err(PagesDirectoryError::new(
            "pages.invalid_directory",
            "directory must not be empty",
            "Provide a local Pages build output directory.",
        ));
    }

    let root = fs::canonicalize(directory).map_err(|err| {
        PagesDirectoryError::new(
            "pages.invalid_directory",
            format!("failed to resolve Pages deployment directory: {err}"),
            "Provide an existing local Pages build output directory.",
        )
    })?;
    let metadata = fs::metadata(&root).map_err(|err| {
        PagesDirectoryError::new(
            "pages.invalid_directory",
            format!("failed to stat Pages deployment directory: {err}"),
            "Check the directory path and permissions.",
        )
    })?;
    if !metadata.is_dir() {
        return Err(PagesDirectoryError::new(
            "pages.invalid_directory",
            "directory must point to a local directory",
            "Provide the Pages build output directory, not a file.",
        ));
    }

    reject_functions_inside_output_directory(&root)?;

    let mut temporary_directories = Vec::new();
    let mut special_files = inspect_special_files(&root)?;
    let functions = include_pages_functions_if_present(
        &root,
        &mut special_files,
        &options,
        &mut temporary_directories,
    )?;
    validate_special_files(&special_files)?;
    let mut assets = Vec::new();
    collect_asset_files(&root, &root, &mut assets)?;
    assets.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let max_files = max_files.clamp(1, MAX_PAGES_ASSET_COUNT_DEFAULT);
    if assets.len() > max_files {
        return Err(PagesDirectoryError::new(
            "pages.too_many_assets",
            format!(
                "Pages deployment contains {} assets, above the configured limit {max_files}",
                assets.len()
            ),
            "Reduce the build output file count or raise max_files up to Cloudflare's current Pages direct-upload limit.",
        ));
    }

    let total_asset_bytes = assets.iter().map(|asset| asset.size_bytes).sum();
    let manifest = assets
        .iter()
        .map(|asset| (format!("/{}", asset.relative_path), asset.hash.clone()))
        .collect::<BTreeMap<_, _>>();
    let manifest_sha256 = stable_json_sha256(&manifest)?;

    Ok(PagesDirectoryPackage {
        root_name: root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("pages-directory")
            .to_string(),
        assets,
        total_asset_bytes,
        special_files,
        functions,
        manifest,
        manifest_sha256,
        temporary_directories,
    })
}

pub(crate) fn chunk_pages_assets(assets: &[PagesAssetFile]) -> Vec<Vec<PagesAssetFile>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 0u64;

    for asset in assets {
        let would_exceed_size = !current.is_empty()
            && current_bytes.saturating_add(asset.size_bytes) > MAX_UPLOAD_BUCKET_BYTES;
        let would_exceed_count = current.len() >= MAX_UPLOAD_BUCKET_FILE_COUNT;
        if would_exceed_size || would_exceed_count {
            batches.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes = current_bytes.saturating_add(asset.size_bytes);
        current.push(asset.clone());
    }

    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

pub(crate) fn read_asset_base64(asset: &PagesAssetFile) -> Result<String, PagesDirectoryError> {
    let bytes = fs::read(&asset.absolute_path).map_err(|err| {
        PagesDirectoryError::new(
            "pages.asset_read_failed",
            format!("failed reading asset {}: {err}", asset.relative_path),
            "Check the Pages deployment directory permissions and retry.",
        )
    })?;
    Ok(BASE64_STANDARD.encode(bytes))
}

fn collect_asset_files(
    root: &Path,
    current: &Path,
    assets: &mut Vec<PagesAssetFile>,
) -> Result<(), PagesDirectoryError> {
    let entries = fs::read_dir(current).map_err(|err| {
        PagesDirectoryError::new(
            "pages.directory_read_failed",
            format!("failed reading Pages deployment directory: {err}"),
            "Check directory permissions and retry.",
        )
    })?;

    for entry in entries {
        let entry = entry.map_err(|err| {
            PagesDirectoryError::new(
                "pages.directory_read_failed",
                format!("failed reading Pages deployment directory entry: {err}"),
                "Check directory permissions and retry.",
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|err| {
            PagesDirectoryError::new(
                "pages.directory_read_failed",
                format!("failed reading Pages deployment file metadata: {err}"),
                "Check directory permissions and retry.",
            )
        })?;
        if metadata.file_type().is_symlink() {
            continue;
        }

        let relative = path.strip_prefix(root).map_err(|err| {
            PagesDirectoryError::new(
                "pages.directory_read_failed",
                format!("failed computing relative Pages deployment path: {err}"),
                "Retry with a normal local directory path.",
            )
        })?;
        if metadata.is_dir() {
            if should_ignore_directory(relative) {
                continue;
            }
            collect_asset_files(root, &path, assets)?;
            continue;
        }
        if !metadata.is_file() || should_ignore_file(relative) {
            continue;
        }
        if metadata.len() > MAX_PAGES_ASSET_BYTES {
            return Err(PagesDirectoryError::new(
                "pages.asset_too_large",
                format!(
                    "Pages asset {} is {} bytes, above Cloudflare's 25 MiB direct-upload limit",
                    normalize_relative_path(relative),
                    metadata.len()
                ),
                "Remove or split the asset before deploying this directory.",
            ));
        }

        let relative_path = normalize_relative_path(relative);
        let hash = hash_pages_asset(&path, &relative_path)?;
        let content_type = mime_guess::from_path(&path)
            .first_or_octet_stream()
            .essence_str()
            .to_string();

        assets.push(PagesAssetFile {
            relative_path,
            absolute_path: path,
            content_type,
            size_bytes: metadata.len(),
            hash,
        });
    }

    Ok(())
}

fn inspect_special_files(root: &Path) -> Result<PagesSpecialFiles, PagesDirectoryError> {
    Ok(PagesSpecialFiles {
        headers: inspect_special_file(root, "_headers", "_headers")?,
        redirects: inspect_special_file(root, "_redirects", "_redirects")?,
        routes: inspect_special_file(root, "_routes.json", "_routes.json")?,
        worker: inspect_special_file(root, "_worker.js", "_worker.js")?,
        worker_bundle: inspect_special_file(root, "_worker.bundle", "_worker.bundle")?,
        functions_filepath_routing_config: None,
    })
}

fn inspect_special_file(
    root: &Path,
    form_name: &'static str,
    file_name: &'static str,
) -> Result<Option<PagesSpecialFile>, PagesDirectoryError> {
    let path = root.join(file_name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(PagesDirectoryError::new(
                "pages.directory_read_failed",
                format!("failed reading {file_name} metadata: {err}"),
                "Check the Pages deployment directory permissions and retry.",
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(None);
    }
    if metadata.len() > MAX_PAGES_ASSET_BYTES {
        return Err(PagesDirectoryError::new(
            "pages.asset_too_large",
            format!(
                "{file_name} is {} bytes, above Cloudflare's 25 MiB direct-upload limit",
                metadata.len()
            ),
            "Shorten the special Pages file before deploying this directory.",
        ));
    }
    Ok(Some(PagesSpecialFile {
        form_name,
        file_name,
        path,
        size_bytes: metadata.len(),
    }))
}

fn validate_special_files(special_files: &PagesSpecialFiles) -> Result<(), PagesDirectoryError> {
    if special_files.worker.is_some() && special_files.worker_bundle.is_some() {
        return Err(PagesDirectoryError::new(
            "pages.worker_conflict",
            "_worker.js and _worker.bundle are both present; Cloudflare Pages accepts only one worker upload format per deployment",
            "Remove one worker artifact before deploying. Use _worker.js for plain JavaScript, or _worker.bundle for Wrangler's multipart Worker bundle output.",
        ));
    }
    if let Some(worker) = special_files.worker.as_ref() {
        if worker_js_looks_like_multipart_bundle(worker)? {
            return Err(PagesDirectoryError::new(
                "pages.worker_js_contains_multipart_bundle",
                "_worker.js appears to contain a multipart Worker bundle rather than plain JavaScript; sending it as _worker.js would make Cloudflare parse a form boundary as worker code",
                "Keep Wrangler's generated multipart bundle named _worker.bundle, or deploy from the full project with Wrangler so the functions bundle is uploaded with the correct field.",
            ));
        }
    }
    if special_files.routes.is_some()
        && special_files.worker.is_none()
        && special_files.worker_bundle.is_none()
    {
        return Err(PagesDirectoryError::new(
            "pages.routes_without_worker",
            "_routes.json is present but _worker.js or _worker.bundle is missing; this looks like a Pages Functions routing artifact without the compiled Functions/advanced-mode Worker bundle",
            "Do not deploy this artifact with pages_deploy_directory. Use Wrangler from the project root so Pages Functions are compiled and uploaded, or provide a build output directory that contains the matching _worker.js or _worker.bundle.",
        ));
    }
    Ok(())
}

fn worker_js_looks_like_multipart_bundle(
    worker: &PagesSpecialFile,
) -> Result<bool, PagesDirectoryError> {
    let mut file = fs::File::open(&worker.path).map_err(|err| {
        PagesDirectoryError::new(
            "pages.directory_read_failed",
            format!("failed reading {}: {err}", worker.file_name),
            "Check the Pages deployment directory permissions and retry.",
        )
    })?;
    let mut prefix = [0u8; 4096];
    let len = file.read(&mut prefix).map_err(|err| {
        PagesDirectoryError::new(
            "pages.directory_read_failed",
            format!("failed reading {}: {err}", worker.file_name),
            "Check the Pages deployment directory permissions and retry.",
        )
    })?;
    let text = String::from_utf8_lossy(&prefix[..len]);
    let trimmed = text.trim_start_matches(|ch: char| ch.is_whitespace());
    Ok(trimmed.starts_with("--")
        && trimmed
            .to_ascii_lowercase()
            .contains("content-disposition: form-data"))
}

fn reject_functions_inside_output_directory(root: &Path) -> Result<(), PagesDirectoryError> {
    let path = root.join("functions");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            return Err(PagesDirectoryError::new(
                "pages.functions_inside_output_directory",
                "functions is present inside the deployment directory; this looks like a Pages project root rather than a build output directory",
                "Provide the static build output directory, such as dist, and optionally project_root so Pages Functions can be bundled before upload.",
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(PagesDirectoryError::new(
                "pages.directory_read_failed",
                format!("failed checking unsupported Pages functions surface: {err}"),
                "Check the Pages deployment directory permissions and retry.",
            ));
        }
    }
    Ok(())
}

fn include_pages_functions_if_present(
    output_root: &Path,
    special_files: &mut PagesSpecialFiles,
    options: &PagesDirectoryInspectOptions,
    temporary_directories: &mut Vec<PathBuf>,
) -> Result<PagesFunctionsSummary, PagesDirectoryError> {
    let project_root = detect_pages_project_root(output_root, options.project_root.as_deref())?;
    let Some(project_root) = project_root else {
        return Ok(PagesFunctionsSummary::default());
    };
    let functions_directory = project_root.join("functions");
    let functions_directory = match fs::symlink_metadata(&functions_directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            functions_directory
        }
        Ok(_) => return Ok(PagesFunctionsSummary::default()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PagesFunctionsSummary::default());
        }
        Err(err) => {
            return Err(PagesDirectoryError::new(
                "pages.directory_read_failed",
                format!("failed checking Pages functions directory: {err}"),
                "Check the Pages project root permissions and retry.",
            ));
        }
    };

    let mut summary = PagesFunctionsSummary {
        detected: true,
        included: false,
        project_root: Some(project_root.display().to_string()),
        functions_directory: Some(functions_directory.display().to_string()),
        ..PagesFunctionsSummary::default()
    };

    if special_files.worker.is_some() || special_files.worker_bundle.is_some() {
        return Ok(summary);
    }

    let build_dir = create_temporary_pages_build_dir()?;
    let worker_bundle_path = build_dir.join("_worker.bundle");
    let generated_routes_path = build_dir.join("_routes.json");
    let filepath_routing_config_path = build_dir.join("functions-filepath-routing-config.json");
    run_wrangler_pages_functions_build(
        output_root,
        &project_root,
        &functions_directory,
        &worker_bundle_path,
        &generated_routes_path,
        &filepath_routing_config_path,
        options.wrangler_bin.as_deref(),
        &mut summary,
    )?;

    let worker_bundle = inspect_existing_special_file(
        worker_bundle_path,
        "_worker.bundle",
        "_worker.bundle",
    )?
    .ok_or_else(|| {
        PagesDirectoryError::new(
            "pages.functions_bundle_missing",
            "Pages Functions not included; Wrangler finished without producing _worker.bundle",
            "Use Wrangler fallback for this deployment until the Functions bundle can be produced locally.",
        )
    })?;
    special_files.worker_bundle = Some(worker_bundle.clone());
    summary.worker_bundle = Some(special_file_summary(&worker_bundle));

    if special_files.routes.is_none() {
        if let Some(routes) =
            inspect_existing_special_file(generated_routes_path, "_routes.json", "_routes.json")?
        {
            special_files.routes = Some(routes.clone());
            summary.generated_routes = Some(special_file_summary(&routes));
        }
    }

    if let Some(config) = inspect_existing_special_file(
        filepath_routing_config_path,
        "functions-filepath-routing-config.json",
        "functions-filepath-routing-config.json",
    )? {
        special_files.functions_filepath_routing_config = Some(config.clone());
        summary.filepath_routing_config = Some(special_file_summary(&config));
    }

    summary.included = true;
    temporary_directories.push(build_dir);
    Ok(summary)
}

fn detect_pages_project_root(
    output_root: &Path,
    explicit_project_root: Option<&str>,
) -> Result<Option<PathBuf>, PagesDirectoryError> {
    if let Some(project_root) = explicit_project_root {
        let trimmed = project_root.trim();
        if trimmed.is_empty() {
            return Err(PagesDirectoryError::new(
                "pages.invalid_project_root",
                "project_root must not be empty when provided",
                "Omit project_root or provide the Pages project root containing functions.",
            ));
        }
        let root = fs::canonicalize(trimmed).map_err(|err| {
            PagesDirectoryError::new(
                "pages.invalid_project_root",
                format!("failed to resolve Pages project root: {err}"),
                "Provide an existing local Pages project root.",
            )
        })?;
        if !root.is_dir() {
            return Err(PagesDirectoryError::new(
                "pages.invalid_project_root",
                "project_root must point to a local directory",
                "Provide the Pages project root containing functions.",
            ));
        }
        return Ok(Some(root));
    }

    for ancestor in output_root.ancestors().skip(1) {
        let functions = ancestor.join("functions");
        if fs::symlink_metadata(&functions)
            .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Ok(Some(ancestor.to_path_buf()));
        }
    }
    Ok(None)
}

fn run_wrangler_pages_functions_build(
    output_root: &Path,
    project_root: &Path,
    functions_directory: &Path,
    worker_bundle_path: &Path,
    generated_routes_path: &Path,
    filepath_routing_config_path: &Path,
    wrangler_bin: Option<&Path>,
    summary: &mut PagesFunctionsSummary,
) -> Result<(), PagesDirectoryError> {
    let wrangler = resolve_wrangler_command(project_root, wrangler_bin);
    summary.wrangler_command = Some(wrangler.display_name.clone());
    let wrangler_config_home = worker_bundle_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir)
        .join("wrangler-config-home");
    fs::create_dir_all(&wrangler_config_home).map_err(|err| {
        PagesDirectoryError::new(
            "pages.functions_bundle_failed",
            format!("failed preparing Wrangler config directory: {err}"),
            "Check local temporary directory permissions and retry.",
        )
    })?;

    let output = Command::new(&wrangler.program)
        .args(&wrangler.prefix_args)
        .args([
            OsString::from("pages"),
            OsString::from("functions"),
            OsString::from("build"),
            functions_directory.as_os_str().to_os_string(),
            OsString::from("--outfile"),
            worker_bundle_path.as_os_str().to_os_string(),
            OsString::from("--project-directory"),
            project_root.as_os_str().to_os_string(),
            OsString::from("--build-output-directory"),
            output_root.as_os_str().to_os_string(),
            OsString::from("--output-routes-path"),
            generated_routes_path.as_os_str().to_os_string(),
            OsString::from("--output-config-path"),
            filepath_routing_config_path.as_os_str().to_os_string(),
        ])
        .current_dir(project_root)
        .env("XDG_CONFIG_HOME", &wrangler_config_home)
        .env("NO_COLOR", "1")
        .output()
        .map_err(|err| {
            PagesDirectoryError::new(
                "pages.functions_bundle_failed",
                format!("failed to run Wrangler Pages Functions build: {err}"),
                "Install Wrangler in the Pages project or set CLOUDFLARE_MCP_WRANGLER_BIN, then retry. Pages Functions not included; use Wrangler fallback if needed.",
            )
        })?;

    if !output.status.success() {
        return Err(PagesDirectoryError::new(
            "pages.functions_bundle_failed",
            format!(
                "Pages Functions not included; Wrangler Pages Functions build exited with status {}. stdout: {} stderr: {}",
                output.status,
                trim_command_output(&output.stdout),
                trim_command_output(&output.stderr)
            ),
            "Use Wrangler fallback for this deployment, or fix the local Functions build and retry pages_deploy_directory.",
        ));
    }

    Ok(())
}

struct WranglerCommand {
    program: OsString,
    prefix_args: Vec<OsString>,
    display_name: String,
}

fn resolve_wrangler_command(project_root: &Path, wrangler_bin: Option<&Path>) -> WranglerCommand {
    if let Some(path) = wrangler_bin {
        return WranglerCommand {
            program: path.as_os_str().to_os_string(),
            prefix_args: Vec::new(),
            display_name: path.display().to_string(),
        };
    }
    if let Ok(path) = std::env::var("CLOUDFLARE_MCP_WRANGLER_BIN") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return WranglerCommand {
                program: OsString::from(trimmed),
                prefix_args: Vec::new(),
                display_name: trimmed.to_string(),
            };
        }
    }
    let local = project_root.join("node_modules/.bin/wrangler");
    if local.exists() {
        return WranglerCommand {
            program: local.as_os_str().to_os_string(),
            prefix_args: Vec::new(),
            display_name: local.display().to_string(),
        };
    }
    WranglerCommand {
        program: OsString::from("npx"),
        prefix_args: vec![OsString::from("--no-install"), OsString::from("wrangler")],
        display_name: "npx --no-install wrangler".to_string(),
    }
}

fn create_temporary_pages_build_dir() -> Result<PathBuf, PagesDirectoryError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let path = std::env::temp_dir().join(format!(
        "cloudflare-mcp-pages-functions-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).map_err(|err| {
        PagesDirectoryError::new(
            "pages.functions_bundle_failed",
            format!("failed creating temporary Pages Functions build directory: {err}"),
            "Check local temporary directory permissions and retry.",
        )
    })?;
    Ok(path)
}

fn inspect_existing_special_file(
    path: PathBuf,
    form_name: &'static str,
    file_name: &'static str,
) -> Result<Option<PagesSpecialFile>, PagesDirectoryError> {
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(PagesDirectoryError::new(
                "pages.directory_read_failed",
                format!("failed reading generated {file_name} metadata: {err}"),
                "Check the local Pages Functions build output and retry.",
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(None);
    }
    if metadata.len() > MAX_PAGES_ASSET_BYTES {
        return Err(PagesDirectoryError::new(
            "pages.asset_too_large",
            format!(
                "generated {file_name} is {} bytes, above Cloudflare's 25 MiB direct-upload limit",
                metadata.len()
            ),
            "Use Wrangler fallback or reduce the generated Pages Functions bundle size.",
        ));
    }
    Ok(Some(PagesSpecialFile {
        form_name,
        file_name,
        path,
        size_bytes: metadata.len(),
    }))
}

fn trim_command_output(output: &[u8]) -> String {
    let text = String::from_utf8_lossy(output);
    let trimmed = text.trim();
    let max_chars = 2_000;
    let mut result = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        result.push_str("...");
    }
    result
}

fn should_ignore_directory(relative: &Path) -> bool {
    first_component(relative)
        .map(|component| {
            matches!(
                component,
                ".git" | "node_modules" | ".wrangler" | "functions"
            )
        })
        .unwrap_or(false)
        || relative
            .components()
            .filter_map(component_text)
            .any(|component| component == ".git" || component == "node_modules")
}

fn should_ignore_file(relative: &Path) -> bool {
    let normalized = normalize_relative_path(relative);
    if normalized == "_headers"
        || normalized == "_redirects"
        || normalized == "_routes.json"
        || normalized == "_worker.js"
        || normalized == "_worker.bundle"
        || normalized == ".DS_Store"
    {
        return true;
    }
    relative
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == ".DS_Store")
        .unwrap_or(false)
}

fn first_component(path: &Path) -> Option<&str> {
    path.components().find_map(component_text)
}

fn component_text<'a>(component: Component<'a>) -> Option<&'a str> {
    match component {
        Component::Normal(value) => value.to_str(),
        _ => None,
    }
}

fn normalize_relative_path(relative: &Path) -> String {
    relative
        .components()
        .filter_map(component_text)
        .collect::<Vec<_>>()
        .join("/")
}

fn hash_pages_asset(path: &Path, relative_path: &str) -> Result<String, PagesDirectoryError> {
    let bytes = fs::read(path).map_err(|err| {
        PagesDirectoryError::new(
            "pages.asset_read_failed",
            format!("failed reading asset {relative_path}: {err}"),
            "Check the Pages deployment directory permissions and retry.",
        )
    })?;
    let extension = Path::new(relative_path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let hash_input = format!("{}{}", BASE64_STANDARD.encode(bytes), extension);
    Ok(blake3::hash(hash_input.as_bytes()).to_hex()[..32].to_string())
}

fn stable_json_sha256<T: Serialize>(value: &T) -> Result<String, PagesDirectoryError> {
    let text = serde_json::to_string(value).map_err(|err| {
        PagesDirectoryError::new(
            "pages.manifest_serialize_failed",
            format!("failed serializing Pages deployment manifest: {err}"),
            "Retry with a normal Pages deployment directory.",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn special_file_summary(file: &PagesSpecialFile) -> PagesSpecialFileSummary {
    PagesSpecialFileSummary {
        name: file.file_name,
        size_bytes: file.size_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_pages_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cloudflare-mcp-pages-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp pages dir");
        path
    }

    fn fake_wrangler(root: &Path) -> PathBuf {
        let path = root.join("fake-wrangler.sh");
        fs::write(
            &path,
            r#"#!/bin/sh
set -eu
outfile=""
routes=""
config=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --outfile)
      shift
      outfile="$1"
      ;;
    --output-routes-path)
      shift
      routes="$1"
      ;;
    --output-config-path)
      shift
      config="$1"
      ;;
  esac
  shift || true
done
test -n "$outfile"
printf '%s' '------formdata-worker-bundle
Content-Disposition: form-data; name="metadata"

{"main_module":"index.js"}
------formdata-worker-bundle
Content-Disposition: form-data; name="index.js"; filename="index.js"

export default {};
------formdata-worker-bundle--
' > "$outfile"
test -z "$routes" || printf '%s' '{"version":1,"include":["/api/*"],"exclude":[]}' > "$routes"
test -z "$config" || printf '%s' '{"routes":[{"routePath":"/api/ping","mountPath":"/api/ping","method":"GET"}]}' > "$config"
"#,
        )
        .expect("write fake wrangler");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path)
                .expect("fake wrangler metadata")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("chmod fake wrangler");
        }
        path
    }

    #[test]
    fn inspect_pages_directory_accepts_advanced_mode_worker_as_special_file() {
        let root = temp_pages_dir("worker");
        fs::write(root.join("index.html"), "<h1>ok</h1>").expect("write index");
        fs::write(
            root.join("_worker.js"),
            "export default { fetch(request, env) { return env.ASSETS.fetch(request); } };",
        )
        .expect("write worker");

        let package = inspect_pages_directory(root.to_str().unwrap(), 20).expect("inspect pages");

        assert_eq!(package.assets.len(), 1);
        assert_eq!(package.assets[0].relative_path, "index.html");
        assert!(package.special_files.worker.is_some());
        assert!(package.special_files.worker_bundle.is_none());
        assert!(!package.manifest.contains_key("/_worker.js"));

        fs::remove_dir_all(root).expect("cleanup temp pages dir");
    }

    #[test]
    fn inspect_pages_directory_accepts_worker_bundle_as_special_file() {
        let root = temp_pages_dir("worker-bundle");
        fs::write(root.join("index.html"), "<h1>ok</h1>").expect("write index");
        fs::write(
            root.join("_worker.bundle"),
            "------formdata-worker-bundle\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n------formdata-worker-bundle--\r\n",
        )
        .expect("write bundle");

        let package = inspect_pages_directory(root.to_str().unwrap(), 20).expect("inspect pages");

        assert_eq!(package.assets.len(), 1);
        assert!(package.special_files.worker.is_none());
        assert!(package.special_files.worker_bundle.is_some());
        assert!(!package.manifest.contains_key("/_worker.bundle"));

        fs::remove_dir_all(root).expect("cleanup temp pages dir");
    }

    #[test]
    fn inspect_pages_directory_bundles_functions_from_detected_project_root() {
        let project = temp_pages_dir("functions-project");
        let dist = project.join("dist");
        fs::create_dir_all(&dist).expect("create dist");
        fs::create_dir_all(project.join("functions/api")).expect("create functions");
        fs::write(dist.join("index.html"), "<h1>ok</h1>").expect("write index");
        fs::write(
            project.join("functions/api/ping.js"),
            "export function onRequest() { return new Response('pong'); }",
        )
        .expect("write function");
        let wrangler = fake_wrangler(&project);

        let package = inspect_pages_directory_with_options(
            dist.to_str().unwrap(),
            20,
            PagesDirectoryInspectOptions {
                project_root: None,
                wrangler_bin: Some(wrangler),
            },
        )
        .expect("inspect pages with functions");

        assert_eq!(package.assets.len(), 1);
        assert_eq!(package.assets[0].relative_path, "index.html");
        assert!(package.special_files.worker.is_none());
        assert!(package.special_files.worker_bundle.is_some());
        assert!(package.special_files.routes.is_some());
        assert!(
            package
                .special_files
                .functions_filepath_routing_config
                .is_some()
        );
        assert!(package.functions.detected);
        assert!(package.functions.included);
        assert_eq!(
            package
                .functions
                .worker_bundle
                .as_ref()
                .map(|file| file.name),
            Some("_worker.bundle")
        );
        assert!(!package.manifest.contains_key("/_worker.bundle"));

        fs::remove_dir_all(project).expect("cleanup temp pages dir");
    }

    #[test]
    fn inspect_pages_directory_rejects_misnamed_worker_bundle() {
        let root = temp_pages_dir("misnamed-worker-bundle");
        fs::write(root.join("index.html"), "<h1>ok</h1>").expect("write index");
        fs::write(
            root.join("_worker.js"),
            "------formdata-worker-bundle\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n------formdata-worker-bundle--\r\n",
        )
        .expect("write worker");

        let error = inspect_pages_directory(root.to_str().unwrap(), 20).expect_err("reject");

        assert_eq!(error.code, "pages.worker_js_contains_multipart_bundle");
        assert!(error.message.contains("multipart Worker bundle"));

        fs::remove_dir_all(root).expect("cleanup temp pages dir");
    }

    #[test]
    fn inspect_pages_directory_rejects_worker_js_and_bundle_together() {
        let root = temp_pages_dir("worker-conflict");
        fs::write(root.join("index.html"), "<h1>ok</h1>").expect("write index");
        fs::write(root.join("_worker.js"), "export default {};").expect("write worker");
        fs::write(
            root.join("_worker.bundle"),
            "------formdata-worker-bundle\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n------formdata-worker-bundle--\r\n",
        )
        .expect("write bundle");

        let error = inspect_pages_directory(root.to_str().unwrap(), 20).expect_err("reject");

        assert_eq!(error.code, "pages.worker_conflict");

        fs::remove_dir_all(root).expect("cleanup temp pages dir");
    }

    #[test]
    fn inspect_pages_directory_rejects_routes_without_worker() {
        let root = temp_pages_dir("routes-without-worker");
        fs::write(root.join("index.html"), "<h1>ok</h1>").expect("write index");
        fs::write(
            root.join("_routes.json"),
            r#"{"version":1,"include":["/*"],"exclude":[]}"#,
        )
        .expect("write routes");

        let error = inspect_pages_directory(root.to_str().unwrap(), 20).expect_err("reject");

        assert_eq!(error.code, "pages.routes_without_worker");
        assert!(
            error
                .message
                .contains("_worker.js or _worker.bundle is missing")
        );

        fs::remove_dir_all(root).expect("cleanup temp pages dir");
    }

    #[test]
    fn inspect_pages_directory_rejects_functions_inside_output_directory() {
        let root = temp_pages_dir("functions");
        fs::write(root.join("index.html"), "<h1>ok</h1>").expect("write index");
        fs::create_dir(root.join("functions")).expect("create functions");

        let error = inspect_pages_directory(root.to_str().unwrap(), 20).expect_err("reject");

        assert_eq!(error.code, "pages.functions_inside_output_directory");
        assert!(error.message.contains("deployment directory"));

        fs::remove_dir_all(root).expect("cleanup temp pages dir");
    }
}
