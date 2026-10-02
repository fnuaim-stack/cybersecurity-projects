$ErrorActionPreference = "Stop"

$Project = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$DemoDb = Join-Path $PSScriptRoot "demo-exposure.db"

if (Test-Path $DemoDb) {
    Remove-Item $DemoDb -Force
}

$LabCommand = "Set-Location '$Project'; py samples\full_demo\demo_lab.py --db '$DemoDb'"
Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $LabCommand

Start-Sleep -Seconds 3
Set-Location $Project
$env:EXPOSURE_DB = $DemoDb
py webapp.py
