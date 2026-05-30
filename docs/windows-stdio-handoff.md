# Windows Stdio Handoff

This handoff runs `cloudflare-mcp` as a local Codex stdio MCP server on
Windows. Codex starts the executable directly and communicates with it over
stdin/stdout; the server does not bind a local HTTP port in this mode.

## Install

1. Create a local tools directory:

   ```powershell
   New-Item -ItemType Directory -Force C:\Tools\cloudflare-mcp
   ```

2. Place `cloudflare-mcp.exe` in that directory.

3. Run the bundled smoke test from the same directory:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\smoke-stdio.ps1 -ExePath .\cloudflare-mcp.exe
   ```

The smoke test uses `CLOUDFLARE_MCP_AUTH_MODE=off` and does not call any
Cloudflare mutating tool.

## Configure Credentials

Store credentials in the Windows user environment. Do not paste real tokens
into `config.toml`.

```powershell
[Environment]::SetEnvironmentVariable("CLOUDFLARE_MCP_API_TOKEN", "<cloudflare_api_token>", "User")
[Environment]::SetEnvironmentVariable("CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID", "<account_id>", "User")
[Environment]::SetEnvironmentVariable("CLOUDFLARE_MCP_DEFAULT_ZONE_ID", "<zone_id>", "User")
```

Open a new terminal after setting user environment variables.

## Codex Config

Add this to `%USERPROFILE%\.codex\config.toml`, adjusting the executable path if
you installed it somewhere else:

```toml
[mcp_servers.cloudflare-mcp]
command = "C:\\Tools\\cloudflare-mcp\\cloudflare-mcp.exe"
args = ["--stdio"]
startup_timeout_sec = 30.0
tool_timeout_sec = 300.0
env_vars = [
  "CLOUDFLARE_MCP_API_TOKEN",
  "CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID",
  "CLOUDFLARE_MCP_DEFAULT_ZONE_ID",
]

[mcp_servers.cloudflare-mcp.env]
CLOUDFLARE_MCP_AUTH_MODE = "off"
```

This is write-capable when the Cloudflare API token has write permissions. Use
a least-privilege token for the intended account and zone.

## Local Checks

From the install directory:

```powershell
.\cloudflare-mcp.exe --stdio --print-tools
.\cloudflare-mcp.exe --stdio
```

The `--stdio --print-tools` command uses the stdio auth default and exits after
printing the registered tool names. The plain `--stdio` command is expected to
wait for a Codex/MCP client; stop it with `Ctrl+C` when running it manually.
