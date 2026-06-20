use mcp_toolkit_core::tool_inventory::{
    ToolCapability, ToolDiscoveryMetadata, ToolInventory, ToolInventoryError,
};

use crate::cache::discovery_entry;

pub(crate) const API_PARITY_FEATURE_FLAG: &str = "api_parity";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ToolSurfaceValidation {
    pub unknown: Vec<String>,
    pub read_only: Vec<String>,
}

pub(crate) fn build_tool_inventory() -> Result<ToolInventory, ToolInventoryError> {
    ToolInventory::from_capabilities(tool_capabilities())
}

pub(crate) fn validate_mutating_tool_subset(
    tool_names: &[String],
) -> Result<ToolSurfaceValidation, ToolInventoryError> {
    if tool_names.is_empty() {
        return Ok(ToolSurfaceValidation::default());
    }
    let inventory = build_tool_inventory()?;
    let mut unknown = Vec::new();
    let mut read_only = Vec::new();

    for tool_name in tool_names {
        match inventory.capability(tool_name.as_str()) {
            None => unknown.push(tool_name.clone()),
            Some(capability) if capability.read_only() => read_only.push(tool_name.clone()),
            Some(_) => {}
        }
    }

    unknown.sort();
    unknown.dedup();
    read_only.sort();
    read_only.dedup();

    Ok(ToolSurfaceValidation { unknown, read_only })
}

fn tool_capabilities() -> Vec<ToolCapability> {
    vec![
        cap("health").with_group("status").with_read_only(true),
        cap("find_tools")
            .with_group("discovery")
            .with_read_only(true),
        gated_api_cap("api_parity_status")
            .with_group("api")
            .with_read_only(true),
        gated_api_cap("api_find_operations")
            .with_group("api")
            .with_read_only(true),
        gated_api_cap("api_get_operation")
            .with_group("api")
            .with_read_only(true),
        gated_api_cap("api_prepare_call")
            .with_group("api")
            .with_read_only(true),
        gated_api_cap("api_read")
            .with_group("api")
            .with_read_only(true),
        gated_api_cap("api_mutate")
            .with_group("api")
            .with_read_only(false),
        cap("account_billing_usage")
            .with_group("billing")
            .with_read_only(true),
        cap("graphql_analytics_query")
            .with_group("analytics")
            .with_read_only(true),
        cap("waf_ruleset_summary")
            .with_group("waf")
            .with_read_only(true),
        cap("waf_security_events_summary")
            .with_group("waf")
            .with_read_only(true),
        cap("waf_rule_activity")
            .with_group("waf")
            .with_read_only(true),
        cap("account_api_tokens")
            .with_group("api")
            .with_read_only(false),
        cap("account_api_token_permission_plan")
            .with_group("api")
            .with_read_only(true),
        cap("list_tunnels")
            .with_group("tunnel")
            .with_read_only(true),
        cap("ensure_tunnel")
            .with_group("tunnel")
            .with_read_only(false),
        cap("generate_tunnel_ingress")
            .with_group("tunnel")
            .with_read_only(true),
        cap("connector_control")
            .with_group("tunnel")
            .with_read_only(false),
        cap("list_dns_records")
            .with_group("dns")
            .with_read_only(true),
        cap("d1_list_databases")
            .with_group("d1")
            .with_read_only(true),
        cap("d1_get_database").with_group("d1").with_read_only(true),
        cap("d1_rename_database")
            .with_group("d1")
            .with_read_only(false),
        cap("d1_delete_database")
            .with_group("d1")
            .with_read_only(false),
        cap("d1_inspect_schema")
            .with_group("d1")
            .with_read_only(true),
        cap("d1_query_read_only")
            .with_group("d1")
            .with_read_only(true),
        cap("d1_validate_query")
            .with_group("d1")
            .with_read_only(true),
        cap("d1_execute_write")
            .with_group("d1")
            .with_read_only(false),
        cap("d1_apply_migrations")
            .with_group("d1")
            .with_read_only(false),
        cap("analytics_engine_query")
            .with_group("analytics_engine")
            .with_read_only(true),
        cap("analytics_engine_validate_query")
            .with_group("analytics_engine")
            .with_read_only(true),
        cap("analytics_engine_describe_schema")
            .with_group("analytics_engine")
            .with_read_only(true),
        cap("analytics_engine_list_datasets")
            .with_group("analytics_engine")
            .with_read_only(true),
        cap("capabilities_check")
            .with_group("status")
            .with_read_only(true),
        cap("pages_list_projects")
            .with_group("pages")
            .with_read_only(true),
        cap("pages_get_project")
            .with_group("pages")
            .with_read_only(true),
        cap("pages_update_project")
            .with_group("pages")
            .with_read_only(false),
        cap("pages_list_deployments")
            .with_group("pages")
            .with_read_only(true),
        cap("pages_get_deployment")
            .with_group("pages")
            .with_read_only(true),
        cap("pages_trigger_deployment")
            .with_group("pages")
            .with_read_only(false),
        cap("pages_deploy_directory")
            .with_group("pages")
            .with_read_only(false),
        cap("pages_retry_deployment")
            .with_group("pages")
            .with_read_only(false),
        cap("pages_rollback_deployment")
            .with_group("pages")
            .with_read_only(false),
        cap("pages_list_domains")
            .with_group("pages")
            .with_read_only(true),
        cap("pages_get_domain")
            .with_group("pages")
            .with_read_only(true),
        cap("pages_ensure_domain")
            .with_group("pages")
            .with_read_only(false),
        cap("pages_retry_domain_validation")
            .with_group("pages")
            .with_read_only(false),
        cap("r2_get_object").with_group("r2").with_read_only(true),
        cap("r2_inspect_object")
            .with_group("r2")
            .with_read_only(true),
        cap("r2_put_object").with_group("r2").with_read_only(false),
        cap("verify_dns_route")
            .with_group("dns")
            .with_read_only(true),
        cap("upsert_dns_cname")
            .with_group("dns")
            .with_read_only(false),
        cap("list_access_apps")
            .with_group("access")
            .with_read_only(true),
        cap("access_get_app")
            .with_group("access")
            .with_read_only(true),
        cap("access_verify_hostname_gate")
            .with_group("access")
            .with_read_only(true),
        cap("upsert_access_app")
            .with_group("access")
            .with_read_only(false),
        cap("list_access_policies")
            .with_group("access")
            .with_read_only(true),
        cap("list_workers")
            .with_group("workers")
            .with_read_only(true),
        cap("get_worker_settings")
            .with_group("workers")
            .with_read_only(true),
        cap("patch_worker_settings")
            .with_group("workers")
            .with_read_only(false),
        cap("queues_list").with_group("queues").with_read_only(true),
        cap("queues_get").with_group("queues").with_read_only(true),
        cap("queues_get_metrics")
            .with_group("queues")
            .with_read_only(true),
        cap("queues_list_consumers")
            .with_group("queues")
            .with_read_only(true),
        cap("queues_health")
            .with_group("queues")
            .with_read_only(true),
        cap("workers_list_scripts")
            .with_group("workers")
            .with_read_only(true),
        cap("workers_get_script_settings")
            .with_group("workers")
            .with_read_only(true),
        cap("workers_upload_script")
            .with_group("workers")
            .with_read_only(false),
        cap("workers_list_tails")
            .with_group("workers")
            .with_read_only(true),
        cap("workers_observability_query_events")
            .with_group("workers")
            .with_read_only(true),
        cap("workers_observability_list_keys")
            .with_group("workers")
            .with_read_only(true),
        cap("workers_observability_list_values")
            .with_group("workers")
            .with_read_only(true),
        cap("bindings_discover")
            .with_group("bindings")
            .with_read_only(true),
        cap("email_routing_get_settings")
            .with_group("email")
            .with_read_only(true),
        cap("email_routing_get_dns")
            .with_group("email")
            .with_read_only(true),
        cap("email_routing_list_rules")
            .with_group("email")
            .with_read_only(true),
        cap("email_routing_get_rule")
            .with_group("email")
            .with_read_only(true),
        cap("email_routing_get_catch_all")
            .with_group("email")
            .with_read_only(true),
        cap("email_routing_list_addresses")
            .with_group("email")
            .with_read_only(true),
        cap("email_routing_get_address")
            .with_group("email")
            .with_read_only(true),
        cap("bulk_redirects_list_lists")
            .with_group("redirects")
            .with_read_only(true),
        cap("bulk_redirects_get_list")
            .with_group("redirects")
            .with_read_only(true),
        cap("bulk_redirects_list_items")
            .with_group("redirects")
            .with_read_only(true),
        cap("bulk_redirects_create_list")
            .with_group("redirects")
            .with_read_only(false),
        cap("bulk_redirects_update_list")
            .with_group("redirects")
            .with_read_only(false),
        cap("bulk_redirects_import_items")
            .with_group("redirects")
            .with_read_only(false),
        cap("bulk_redirects_get_operation")
            .with_group("redirects")
            .with_read_only(true),
        cap("bulk_redirects_get_ruleset")
            .with_group("redirects")
            .with_read_only(true),
        cap("bulk_redirects_attach_list_to_ruleset")
            .with_group("redirects")
            .with_read_only(false),
        cap("cache_purge").with_group("cache").with_read_only(false),
        cap("cache_zone_setting")
            .with_group("cache")
            .with_read_only(false),
        cap("cache_rules").with_group("cache").with_read_only(false),
        cap("cache_reserve")
            .with_group("cache")
            .with_read_only(false),
        cap("cache_tiered")
            .with_group("cache")
            .with_read_only(false),
        cap("cache_variants")
            .with_group("cache")
            .with_read_only(false),
        cap("cache_origin_regions")
            .with_group("cache")
            .with_read_only(false),
        cap("replace_access_policies")
            .with_group("access")
            .with_read_only(false),
        cap("apply_access_allowlist")
            .with_group("access")
            .with_read_only(false),
        cap("publish_preflight")
            .with_group("publish")
            .with_read_only(true),
        cap("verify_http_gate")
            .with_group("verification")
            .with_read_only(true),
        cap("portal_agent_request")
            .with_group("portal")
            .with_read_only(false),
        cap("lock_first_publish")
            .with_group("publish")
            .with_read_only(false),
        cap("emergency_unpublish")
            .with_group("publish")
            .with_read_only(false),
    ]
}

fn cap(name: &'static str) -> ToolCapability {
    let capability = ToolCapability::new(name);
    if let Some(entry) = discovery_entry(name) {
        capability.with_discovery(ToolDiscoveryMetadata::new(
            entry.description,
            entry.keywords,
        ))
    } else {
        capability.with_discovery(ToolDiscoveryMetadata::new(name.replace('_', " "), [name]))
    }
}

fn gated_api_cap(name: &'static str) -> ToolCapability {
    cap(name).with_feature_flag(API_PARITY_FEATURE_FLAG)
}
