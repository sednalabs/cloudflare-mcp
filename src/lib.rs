//! # cloudflare-mcp
//!
//! Streamable HTTP MCP server for Cloudflare tunnel/DNS/Access/Pages/D1/Queues/Workers operations.

pub mod access_app;
pub mod api_catalog;
pub(crate) mod api_permissions;
pub mod cache;
pub mod cloudflare;
pub mod config;
#[allow(dead_code)] // staged evidence boundary; provider dispatch and graph consumers are separate
pub(crate) mod d1_catalog_evidence;
pub(crate) mod d1_execute_write;
pub(crate) mod d1_migration_additive;
pub(crate) mod d1_migration_bootstrap;
pub(crate) mod d1_migration_bootstrap_recovery;
pub(crate) mod d1_migration_lease;
pub(crate) mod d1_migration_manifest;
pub(crate) mod d1_migration_reconciliation;
pub(crate) mod d1_migration_seed_rows;
pub(crate) mod d1_migration_terminal;
pub(crate) mod d1_migration_terminal_semantics;
#[allow(dead_code)] // staged pure graph; DML composition and execution are separate successors
pub(crate) mod d1_reserved_relation_graph;
pub(crate) mod d1_target;
pub mod dns_route;
pub mod mutation;
pub(crate) mod pages_deploy;
pub mod policy;
pub mod portal;
#[allow(dead_code)] // staged low-level boundary; lifecycle consumers are intentionally out of scope
pub(crate) mod private_file_custody;
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

pub type McpError = rmcp::ErrorData;
