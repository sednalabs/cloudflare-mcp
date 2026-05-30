param(
    [string]$ExePath = ".\cloudflare-mcp.exe",
    [int]$TimeoutSeconds = 15
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Executable not found: $ExePath"
}

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = (Resolve-Path -LiteralPath $ExePath).Path
$psi.Arguments = "--stdio"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.Environment["CLOUDFLARE_MCP_AUTH_MODE"] = "off"
$psi.Environment["RUST_LOG"] = "warn"

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $psi

function Send-JsonLine {
    param([object]$Payload)
    $line = $Payload | ConvertTo-Json -Depth 32 -Compress
    $process.StandardInput.WriteLine($line)
    $process.StandardInput.Flush()
}

function Read-JsonLine {
    param([int]$ExpectedId)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        $task = $process.StandardOutput.ReadLineAsync()
        if (-not $task.Wait($remaining)) {
            break
        }
        $line = $task.Result
        if ($null -eq $line) {
            break
        }
        if ($line.Trim().Length -eq 0) {
            continue
        }
        $message = $line | ConvertFrom-Json
        if ($message.id -eq $ExpectedId) {
            return $message
        }
    }
    throw "Timed out waiting for JSON-RPC response id $ExpectedId"
}

try {
    if (-not $process.Start()) {
        throw "Failed to start $ExePath"
    }

    Send-JsonLine @{
        jsonrpc = "2.0"
        id = 1
        method = "initialize"
        params = @{
            protocolVersion = "2025-11-25"
            capabilities = @{}
            clientInfo = @{
                name = "cloudflare-mcp-stdio-smoke"
                version = "0.1.0"
            }
        }
    }
    $initialize = Read-JsonLine -ExpectedId 1
    if ($initialize.error) {
        throw "initialize failed: $($initialize.error | ConvertTo-Json -Depth 12 -Compress)"
    }

    Send-JsonLine @{
        jsonrpc = "2.0"
        method = "notifications/initialized"
        params = @{}
    }

    Send-JsonLine @{
        jsonrpc = "2.0"
        id = 2
        method = "tools/list"
        params = @{}
    }
    $tools = Read-JsonLine -ExpectedId 2
    $toolNames = @($tools.result.tools | ForEach-Object { $_.name })
    if ($toolNames -notcontains "cloudflare.health") {
        throw "cloudflare.health was not listed by the stdio server"
    }

    Send-JsonLine @{
        jsonrpc = "2.0"
        id = 3
        method = "tools/call"
        params = @{
            name = "cloudflare.health"
            arguments = @{}
        }
    }
    $health = Read-JsonLine -ExpectedId 3
    if ($health.error) {
        throw "cloudflare.health failed: $($health.error | ConvertTo-Json -Depth 12 -Compress)"
    }

    Write-Host "cloudflare-mcp stdio smoke passed"
}
finally {
    if ($process -and -not $process.HasExited) {
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(1000)) {
            $process.Kill()
            $process.WaitForExit()
        }
    }
    if ($process) {
        $stderr = $process.StandardError.ReadToEnd()
        if ($stderr.Trim().Length -gt 0) {
            Write-Verbose $stderr
        }
        $process.Dispose()
    }
}
