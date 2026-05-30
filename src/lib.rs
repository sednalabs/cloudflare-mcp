//! # cloudflare-mcp
//!
//! Streamable HTTP MCP server for Cloudflare tunnel/DNS/Access/Pages/D1/Queues/Workers operations.

pub mod access_app;
pub mod api_catalog;
pub mod cache;
pub mod cloudflare;
pub mod config;
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
pub mod verification;

pub type McpError = rmcp::ErrorData;
