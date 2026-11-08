param([switch]$VerifyFull)
$ErrorActionPreference = 'Stop'
$base = 'C:\backups\meshtool-recovery'
$start = [DateTime]::UtcNow
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$groups = @($id.Groups | ForEach-Object { $_.Value })
$proof = [ordered]@{
  startedAt=$start.ToString('o'); user=$id.Name
  sessionId=[System.Diagnostics.Process]::GetCurrentProcess().SessionId
  userInteractive=[Environment]::UserInteractive
  batchLogon=($groups -contains 'S-1-5-3')
  interactiveLogon=($groups -contains 'S-1-5-4')
  fullVerification=[bool]$VerifyFull; ok=$false
}
try {
  if ($proof.sessionId -ne 0 -or $proof.userInteractive -or -not $proof.batchLogon -or $proof.interactiveLogon) { throw 'noninteractive_batch_logon_required' }
  $nodeArgs = @("$base\offsite.mjs")
  if ($VerifyFull) { $nodeArgs += '--force-verify' }
  & 'C:\Program Files\nodejs\node.exe' @nodeArgs >> "$base\unattended-run.log" 2>&1
  if ($LASTEXITCODE -ne 0) { throw "backup_exit_$LASTEXITCODE" }
  $last = Get-Content "$base\last-run.json" -Raw | ConvertFrom-Json
  if (-not $last.ok -or [DateTime]::Parse($last.at).ToUniversalTime() -lt $start) { throw 'no_fresh_runner_success' }
  $receipt = Get-Content "$base\latest-verified.json" -Raw | ConvertFrom-Json
  if ($VerifyFull -and ([DateTime]::Parse($receipt.verifiedAt).ToUniversalTime() -lt $start -or -not $receipt.remoteDownloadMatched -or $receipt.browserUid -ne 1000 -or -not $receipt.ownershipAndModesVerified -or $receipt.postgresTablesRestored -lt 1)) { throw 'fresh_full_restore_required' }
  $proof.ok=$true; $proof.completedAt=[DateTime]::UtcNow.ToString('o')
  $proof.source=$receipt.source; $proof.restoreVerifiedAt=$receipt.verifiedAt
  $proof.object=$receipt.object; $proof.filesVerified=$receipt.filesVerified
  $proof.browserUid=$receipt.browserUid; $proof.postgresTablesRestored=$receipt.postgresTablesRestored
  $proof | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 "$base\unattended-proof.json"
  exit 0
} catch {
  $proof.error=$_.Exception.Message
  $proof | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 "$base\unattended-proof.json"
  exit 1
}
