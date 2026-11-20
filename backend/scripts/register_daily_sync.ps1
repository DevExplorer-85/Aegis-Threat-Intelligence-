$ErrorActionPreference = "Stop"

$backendDirectory = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $backendDirectory "venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Python environment not found at $python"
}

$action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "-m scripts.sync_feeds" `
    -WorkingDirectory $backendDirectory
$trigger = New-ScheduledTaskTrigger -Daily -At "6:00 AM"
$principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName "cti-feed-sync" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "Incrementally sync public MISP OSINT feeds" `
    -Force | Out-Null

Write-Output "Registered daily public MISP feed sync at 6:00 AM for the current user."
