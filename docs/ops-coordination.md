# Maintainer coordination

Maintainers may track larger changes in GitHub issues or another project
tracker, but repository changes should remain understandable from public
repository context. Contributors should not need access to private chat history,
internal work-item names, or an external system to understand why a change
exists.

For substantial changes, use a parent issue or summary plus focused child tasks
when the work spans independent areas such as documentation, runtime behavior,
security review, Toolkit changes, and release validation.

Each tracked change should make the following clear somewhere in the public
issue, pull request, or repository documentation:

- Rationale: why the work is useful.
- Objective: what success looks like.
- Scope: what is included and excluded.
- Implementation guidance: important constraints or safety requirements.
- References: relevant files, documentation, issues, upstream sources, and
  related changes.

When work is primarily being used to develop a reusable Rust MCP Toolkit
capability, identify that explicitly and link the corresponding Toolkit change
when one exists. Keep the Cloudflare-specific integration and the reusable MCP
primitive conceptually separate so reviewers can see what is expected to remain
here and what is expected to move upstream.

Keep project scope and operator guidance in [PROJECT_SCOPE.md](PROJECT_SCOPE.md),
[../README.md](../README.md), [RUNBOOK.md](RUNBOOK.md), and
[SECURITY_MODEL.md](SECURITY_MODEL.md).
