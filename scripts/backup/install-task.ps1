$ErrorActionPreference='Stop'
$existing=Get-ScheduledTask -TaskName 'meshtool-seat-workspace-backup'
if($existing.Principal.LogonType.ToString() -eq 'S4U') {
  if($existing.Actions.Execute -ne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $existing.Actions.Arguments -notlike '*run-unattended.ps1*'){throw 'unexpected_backup_action'}
  $existing | Select-Object TaskName,State,@{n='LogonType';e={$_.Principal.LogonType.ToString()}}
  exit 0
}
& "$PSScriptRoot\enable-unattended.ps1"
exit $LASTEXITCODE
