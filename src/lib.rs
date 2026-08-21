//! # cloudflare-mcp
//!
//! Streamable HTTP MCP server for Cloudflare tunnel/DNS/Access/Pages/D1/Queues/Workers operations.

pub mod access_app;
pub mod api_catalog;
pub(crate) mod api_permissions;
pub mod cache;
pub mod cloudflare;
pub mod config;
pub(crate) mod d1_migration_additive;
pub(crate) mod d1_migration_bootstrap;
pub(crate) mod d1_migration_bootstrap_recovery;
pub(crate) mod d1_migration_lease;
pub(crate) mod d1_migration_manifest;
pub(crate) mod d1_migration_reconciliation;
pub(crate) mod d1_migration_seed_rows;
pub(crate) mod d1_migration_terminal;
pub(crate) mod d1_migration_terminal_semantics;
pub mod dns_route;
pub mod mutation;
pub(crate) mod pages_deploy;
pub mod policy;
pub mod portal;
pub mod publish;
pub mod resources;
pub mod server;
pub(crate) mod sql_preflight;
pub(crate) mod tool_surface;
pub mod tools;
pub mod tunnel;
pub mod upstream_oauth;
pub mod verification;
pub(crate) mod worker_upload;
pub(crate) mod worker_version_approval;

/// Route-less local operator helper. It performs no provider I/O.
pub fn retire_worker_version_approval_root(
    root: &std::path::Path,
    generation: &str,
) -> Result<(), String> {
    worker_version_approval::retire_worker_version_approval_root(root, generation)
        .map_err(|error| format!("{}: {}", error.code, error.message))
}
pub(crate) mod worker_version_attempt;
pub(crate) mod worker_version_upload;

pub type McpError = rmcp::ErrorData;
