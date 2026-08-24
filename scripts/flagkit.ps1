[CmdletBinding()]
param(
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
$hostAddress = if ($env:FLAGKIT_HOST) { $env:FLAGKIT_HOST } else { "127.0.0.1" }
$portText = if ($env:PORT) { $env:PORT } else { "8080" }
$port = 0

if (-not [int]::TryParse($portText, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
    throw "PORT must be a whole number between 1 and 65535 (received '$portText')."
}

$pythonCommand = Get-Command "py.exe" -ErrorAction SilentlyContinue
$pythonArguments = @()
if ($pythonCommand) {
    $pythonArguments += "-3"
} else {
    $pythonCommand = Get-Command "python.exe" -ErrorAction SilentlyContinue
}

if (-not $pythonCommand) {
    throw "Python 3 is required. Install it from https://www.python.org/downloads/windows/."
}

$url = "http://localhost:$port"
Write-Host "FlagKit is available at $url" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop FlagKit."

if (-not $NoBrowser) {
    Start-Process $url
}

$pythonArguments += @(
    "-m", "http.server", $port.ToString(),
    "--bind", $hostAddress,
    "--directory", $projectDirectory
)

& $pythonCommand.Source @pythonArguments
exit $LASTEXITCODE
