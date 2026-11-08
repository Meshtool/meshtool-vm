$ErrorActionPreference = 'Stop'
$base = 'C:\backups\meshtool-recovery'
$action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\conhost.exe' -Argument '--headless "C:\Program Files\nodejs\node.exe" "C:\backups\meshtool-recovery\offsite.mjs"' -WorkingDirectory $base
$existing = Get-ScheduledTask -TaskName 'hq-weekly-estate-backup'
$principal = New-ScheduledTaskPrincipal -UserId $existing.Principal.UserId -LogonType Interactive -RunLevel Limited
$daily = New-ScheduledTaskTrigger -Daily -At '03:00'
$login = New-ScheduledTaskTrigger -AtLogOn -User $existing.Principal.UserId
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'meshtool-seat-workspace-backup' -Action $action -Trigger @($daily,$login) -Principal $principal -Settings $settings -Description 'Download-verified encrypted Meshtool seat/workspace backup to existing R2; isolated restore, no live service changes.' | Select-Object TaskName,State
