<#
.SYNOPSIS
    Builds the three demo reports from fictional data: P2 (index.html), P1 (p1.html) and Free (free.html).
.DESCRIPTION
    Runs Get-EntraIDAdminReport.ps1 against the fictional tenant in demo-mock.ps1. No real tenant is contacted.
    The Free demo has security defaults enabled. Run it from the repository root or from anywhere:
        pwsh -File tools\Build-Demos.ps1
.PARAMETER OutDir
    Folder for the three HTML files. Defaults to docs\demo.
#>
param([string]$OutDir = (Join-Path $PSScriptRoot '..\docs\demo'))

$ErrorActionPreference = 'Stop'
$report = (Resolve-Path (Join-Path $PSScriptRoot '..\Get-EntraIDAdminReport.ps1')).Path
$mock = Join-Path $PSScriptRoot 'demo-mock.ps1'
$stub = Join-Path $PSScriptRoot 'stub-module\Microsoft.Graph.Authentication'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$demos = @(
    @{ File = 'index.html'; Baseline = 'P2';   SecurityDefaults = $false }
    @{ File = 'p1.html';    Baseline = 'P1';   SecurityDefaults = $false }
    @{ File = 'free.html';  Baseline = 'Free'; SecurityDefaults = $true }
)
foreach ($demo in $demos) {
    $out = Join-Path $OutDir $demo.File
    $env:DEMO_BASELINE = $demo.Baseline
    $env:DEMO_SECURITYDEFAULTS = if ($demo.SecurityDefaults) { 'on' } else { $null }
    # A fresh process per demo keeps the shadowed Graph functions and the environment switches apart
    pwsh -NoProfile -Command "`$env:PSModulePath = '$(Split-Path $stub)' + [IO.Path]::PathSeparator + `$env:PSModulePath; Import-Module '$stub' -Force; & '$mock' -Script '$report' -Out '$out'" | Out-Null
    if (-not (Test-Path $out)) { throw "Demo not written: $($demo.File)" }
    Write-Host "Built $($demo.File) ($($demo.Baseline))" -ForegroundColor Green
}
$env:DEMO_BASELINE = $null; $env:DEMO_SECURITYDEFAULTS = $null
