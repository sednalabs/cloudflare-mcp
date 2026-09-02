mod analytics_engine;
pub(crate) mod bulk_redirects;
mod capabilities;
pub mod client;
#[allow(dead_code)] // staged internal provider-custody boundary; no public tool route yet
pub(crate) mod d1_catalog;
#[allow(dead_code)] // staged low-level boundary; lifecycle consumers are intentionally out of scope
pub(crate) mod d1_import_upload;
mod email_routing;
pub mod model;
mod pages;
mod queues;
mod workers_observability;

pub use client::{
    AdapterError, AdapterErrorPayload, CloudflareClient, with_request_api_token_override,
};
pub use model::{
    AccessAppUpsertRequest, AccessApplication, AccessPolicy, AccessPolicyWrite,
    BulkRedirectItemWrite, CacheRule, CacheRuleset, D1Database, DnsRecord, DnsRecordUpsertRequest,
    DnsRouteDisableResult, Page, PageInfo, PagesDeployment, PagesDeploymentTriggerRequest,
    PagesDomain, PagesProject, Queue, RulesList, RulesListOperation, Ruleset, Tunnel,
};
