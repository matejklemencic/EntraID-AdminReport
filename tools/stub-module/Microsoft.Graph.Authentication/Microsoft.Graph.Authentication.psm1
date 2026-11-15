# Stub for tests: the demo generator defines the real behaviour. Never contacts Microsoft Graph.
function Connect-MgGraph { }
function Get-MgContext { @{ TenantId = 'demo' } }
function Disconnect-MgGraph { }
function Invoke-MgGraphRequest { throw 'Stub: run tools\Build-Demos.ps1 so the demo generator provides the data.' }
