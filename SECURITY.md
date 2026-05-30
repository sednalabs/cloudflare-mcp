# Security Policy

`cloudflare-mcp` can perform privileged Cloudflare operations. Treat
configuration, credentials, and public issue text with care.

## Reporting Vulnerabilities

If you believe you have found a vulnerability, please report it privately to
the maintainers. Do not open a public issue with exploit details, secrets,
tokens, hostnames, or account identifiers.

If this repository is mirrored or forked, use the security contact for the
maintaining organization of that fork.

## Supported Versions

Until the first stable release, security fixes target the default branch.

## Secret Handling

Do not commit:

- Cloudflare API tokens.
- OAuth client secrets.
- R2 access keys.
- Access service token secrets.
- External service bridge credentials.
- Local environment files containing real credentials.

Prefer environment variables or protected secret files outside the repository.
When using secret file settings, keep files readable only by the owner.

## Safe Public Reports

When opening public issues or pull requests:

- Redact hostnames, user names, account IDs, zone IDs, and token fragments.
- Use placeholders such as `<account_id>`, `<zone_id>`, and `<issuer-url>`.
- Avoid pasting full logs when a short excerpt is enough.
- Do not include private endpoint URLs or internal deployment names.

## Deployment Notes

- Keep HTTP binds on loopback unless MCP auth is enabled.
- Use least-privilege Cloudflare API tokens.
- Use read-only mode for audit sessions.
- Run mutating tools with `dry_run=true` before apply.
- Enable elicitation approval gates when human confirmation is required for
  dangerous apply calls.
