@{
    RootModule        = 'OfficeLoad.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '5d0f7c1e-2b8a-4c55-9a51-7e3f0b6a9c21'
    Author            = 'winlab'
    Description       = 'Start, stop and watch the winlab office load engine from inside the lab.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Start-OfficeLoad', 'Stop-OfficeLoad', 'Get-OfficeLoad')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
