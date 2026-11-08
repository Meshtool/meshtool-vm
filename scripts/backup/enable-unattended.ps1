# One scoped elevation: test S4U for the existing backup user; promote only on full proof.
$ErrorActionPreference='Stop'
$base='C:\backups\meshtool-recovery'
$name='meshtool-seat-workspace-backup'
$candidate='meshtool-seat-backup-s4u-test'
$status=[ordered]@{startedAt=[DateTime]::UtcNow.ToString('o');stage='starting';ok=$false}
function Save-Status { $status | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 "$base\unattended-install.json" }
try {
 $admin=([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
 if(-not $admin){throw 'administrator_elevation_required'}
 $old=Get-ScheduledTask -TaskName $name
 if($old.Principal.LogonType.ToString() -ne 'Interactive'){throw 'unexpected_existing_logon_mode'}
 if(Get-ScheduledTask -TaskName $candidate -ErrorAction SilentlyContinue){throw 'candidate_task_already_exists'}
 Export-ScheduledTask -TaskName $name | Set-Content -Encoding Unicode "$base\task-before-unattended.xml"
 $principal=New-ScheduledTaskPrincipal -UserId $old.Principal.UserId -LogonType S4U -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 $powershell='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
 $testAction=New-ScheduledTaskAction -Execute $powershell -Argument '-NoProfile -File "C:\backups\meshtool-recovery\run-unattended.ps1" -VerifyFull' -WorkingDirectory $base
 Register-ScheduledTask -TaskName $candidate -Action $testAction -Principal $principal -Settings $settings -Description 'Temporary full noninteractive backup proof; no live service changes.' | Out-Null
 $status.stage='testing-s4u'; Save-Status
 $testStart=[DateTime]::UtcNow
 Start-ScheduledTask -TaskName $candidate
 $deadline=[DateTime]::UtcNow.AddMinutes(15)
 do {
  Start-Sleep -Seconds 3
  $info=Get-ScheduledTaskInfo -TaskName $candidate
  $state=(Get-ScheduledTask -TaskName $candidate).State.ToString()
  if($info.LastRunTime.ToUniversalTime() -ge $testStart.AddSeconds(-2) -and $state -ne 'Running'){break}
 } while([DateTime]::UtcNow -lt $deadline)
 if($state -eq 'Running'){throw 'candidate_timeout_original_unchanged'}
 if($info.LastTaskResult -ne 0){throw "candidate_exit_$($info.LastTaskResult)_original_unchanged"}
 $proof=Get-Content "$base\unattended-proof.json" -Raw | ConvertFrom-Json
 if(-not $proof.ok -or -not $proof.fullVerification -or $proof.sessionId -ne 0 -or -not $proof.batchLogon -or $proof.userInteractive -or [DateTime]::Parse($proof.startedAt).ToUniversalTime() -lt $testStart.AddSeconds(-2)){throw 'candidate_proof_failed_original_unchanged'}
 Copy-Item "$base\unattended-proof.json" "$base\unattended-full-proof.json"
 $action=New-ScheduledTaskAction -Execute $powershell -Argument '-NoProfile -File "C:\backups\meshtool-recovery\run-unattended.ps1"' -WorkingDirectory $base
 $daily=New-ScheduledTaskTrigger -Daily -At '03:00'
 $startup=New-ScheduledTaskTrigger -AtStartup
 $startup.Delay='PT5M'
 Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Trigger @($daily,$startup) -Description 'Noninteractive encrypted Meshtool offsite backup and isolated restore; S4U, no stored Windows password.' -Force | Out-Null
 Export-ScheduledTask -TaskName $name | Set-Content -Encoding Unicode "$base\task-unattended.xml"
 $status.stage='promoted';$status.ok=$true;$status.completedAt=[DateTime]::UtcNow.ToString('o');$status.logonType=(Get-ScheduledTask -TaskName $name).Principal.LogonType.ToString();Save-Status
 # The temporary test definition is disabled and retained as evidence.
 Disable-ScheduledTask -TaskName $candidate | Out-Null
 Start-ScheduledTask -TaskName $name
} catch {
 $status.error=$_.Exception.Message;Save-Status
 exit 1
}
