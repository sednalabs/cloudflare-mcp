# Project scope

`cloudflare-mcp` does not aim to duplicate Cloudflare's official MCP catalog.
The official services should normally be used for broad API coverage, current
documentation, and product-specific capabilities that already fit the task.

A local capability belongs in this repository for one of two main reasons:

1. it provides a useful self-hosted Cloudflare operator workflow; or
2. it provides a realistic integration, conformance, or stress-test case for a
   reusable Rust MCP Toolkit capability that can be developed here and then
   upstreamed to the Toolkit.

## Operator value

A curated tool has clear operator value when it provides something concrete
beyond the underlying Cloudflare endpoint, such as:

- a local safety, read-only, or approval rule;
- a repeatable multi-step plan/apply/readback workflow;
- binding between a local artifact or exact input and the operation being
  approved;
- a useful self-hosted credential or network boundary;
- additional verification, rollback, or recovery behavior around a production
  change.

If an official Cloudflare MCP already covers a capability well and none of those
apply, prefer the official MCP rather than adding another first-class wrapper
solely for endpoint coverage.

## Toolkit development and conformance

This repository is also a real-world proving ground for the Rust MCP Toolkit.
Some overlap with an official Cloudflare MCP can therefore be worthwhile when
it exercises a reusable MCP capability under realistic load or workflow
conditions that would be difficult to validate with a small synthetic fixture.

Examples include tool discovery and deferred loading across a large inventory,
strict read-only filtering, authentication and credential boundaries,
elicitation approval, structured mutation evidence, resources, error shaping,
and release provenance.

When a feature is added primarily for Toolkit development, the contribution
should identify the reusable behavior being exercised. Reusable implementation
should move to `mcp-toolkit-rs` once it is sufficiently proven, leaving only the
Cloudflare-specific integration in this repository. Toolkit incubation is a
reason to implement a meaningful case here; it is not a reason to mirror every
Cloudflare product or endpoint.

## Generic API coverage

The generic OpenAPI executor remains useful as a local fallback. Keeping its
catalog reasonably current is part of maintaining that fallback, but matching
Cloudflare's managed product catalog endpoint-for-endpoint is not a project
goal.

Existing curated tools should be held to the same standard. They can be
simplified or retired if the official services make them redundant and they no
longer provide either meaningful operator value or useful ongoing Toolkit
conformance coverage.

For task-by-task routing, see [AGENT_ROUTING.md](AGENT_ROUTING.md). For the
detailed comparison with Cloudflare's official services, see
[OFFICIAL_MCP_COMPARISON.md](OFFICIAL_MCP_COMPARISON.md). For the Toolkit
stress-test role, see [CONFORMANCE_DOGFOOD.md](CONFORMANCE_DOGFOOD.md).
