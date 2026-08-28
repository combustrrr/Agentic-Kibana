[CmdletBinding()]
param(
    [ValidateSet('start', 'scan', 'refresh', 'serve', 'status', 'branches')]
    [string]$Command = 'start',
    [switch]$Scan,
    [switch]$Open,
    [string]$Branch,
    [string]$Repository,
    [int]$Port = 8787
)

$ErrorActionPreference = 'Stop'
$arguments = @('scripts/code_analysis/local_service.py', $Command, '--port', $Port)
if ($Scan) { $arguments += '--scan' }
if ($Open) { $arguments += '--open' }
if ($Branch) { $arguments += @('--branch', $Branch) }
if ($Repository) { $arguments += @('--repository', $Repository) }

& python @arguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
