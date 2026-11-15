@{
    RootModule        = 'Microsoft.Graph.Authentication.psm1'
    ModuleVersion     = '2.99.0'
    GUID              = '0d1b3a52-7c1e-4d7b-9a55-0f3d2c6b7e11'
    FunctionsToExport = @('Connect-MgGraph', 'Get-MgContext', 'Disconnect-MgGraph', 'Invoke-MgGraphRequest')
}
