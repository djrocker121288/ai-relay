$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptRoot
$BinDir = Join-Path $Root 'dist'
if (!(Test-Path $BinDir)) { $BinDir = $ScriptRoot }
$Work = if ($env:AI_RELAY_NATIVE_TEST_DIR) { $env:AI_RELAY_NATIVE_TEST_DIR } else { Join-Path (Get-Location) ('ai-relay-windows-test-' + [Guid]::NewGuid().ToString('N')) }
New-Item -ItemType Directory -Force $Work | Out-Null
$Work = (Resolve-Path $Work).Path
$gateway = Join-Path $BinDir 'ai-relay-gateway-windows-amd64.exe'
$agent = Join-Path $BinDir 'ai-relay-agent-windows-amd64.exe'
if (!(Test-Path $gateway) -or !(Test-Path $agent)) { throw 'Windows amd64 binaries are missing' }
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($identity in @([Security.Principal.WindowsIdentity]::GetCurrent().Name,'S-1-5-18','S-1-5-32-544')) {
  $sid = if ($identity -match '^S-1-') { New-Object Security.Principal.SecurityIdentifier($identity) } else { (New-Object Security.Principal.NTAccount($identity)).Translate([Security.Principal.SecurityIdentifier]) }
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
Set-Acl -LiteralPath $Work -AclObject $acl
function Protect-NativeFile([string]$Path) {
  $fileAcl = New-Object Security.AccessControl.FileSecurity
  $fileAcl.SetAccessRuleProtection($true, $false)
  foreach ($identity in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')) {
    $sid = New-Object Security.Principal.SecurityIdentifier($identity)
    $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')))
  }
  Set-Acl -LiteralPath $Path -AclObject $fileAcl
}
function Wait-Gate([scriptblock]$Condition, [string]$Description) {
  $deadline = [DateTime]::UtcNow.AddSeconds(45)
  do {
    if (& $Condition) { return }
    Start-Sleep -Milliseconds 500
  } while ([DateTime]::UtcNow -lt $deadline)
  throw "Timed out: $Description; inspect logs in $Work"
}
function Start-Gateway {
  Start-Process -FilePath $gateway -ArgumentList "-listen 127.0.0.1:18743 -state `"$(Join-Path $Work 'state')`"" -RedirectStandardOutput (Join-Path $Work 'gateway.log') -RedirectStandardError (Join-Path $Work 'gateway.err') -PassThru
}
function Start-Agent {
  $args = "-gateway http://127.0.0.1:18743 -credential-file `"$(Join-Path $Work 'agent.cred')`""
  if (!(Test-Path (Join-Path $Work 'agent.cred'))) { $args += " -enroll-token-file `"$(Join-Path $Work 'enroll.token')`"" }
  Start-Process -FilePath $agent -ArgumentList $args -RedirectStandardOutput (Join-Path $Work 'agent.log') -RedirectStandardError (Join-Path $Work 'agent.err') -PassThru
}
function Wait-Health {
  Wait-Gate { if ($gw.HasExited) { throw 'Gateway exited before health check' }; try { $null = Invoke-RestMethod http://127.0.0.1:18743/healthz -TimeoutSec 2; $true } catch { $false } } 'gateway health'
}
function Submit-Command([string]$Marker) {
  $body = @{ jsonrpc='2.0'; id=1; method='tools/call'; params=@{ name='agent.exec'; arguments=@{ device_id=$cred.device_id; command='cmd.exe'; args=@('/c','echo',$Marker) } } } | ConvertTo-Json -Depth 8
  $response = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:18743/mcp -Headers $headers -Body $body -ContentType application/json -TimeoutSec 10
  if ($response.error -or !$response.result.id) { throw ('MCP submit failed: ' + ($response | ConvertTo-Json -Depth 10)) }
  $response.result.id
}
function Assert-Job([string]$JobId, [string]$Marker) {
  Wait-Gate {
    $job = Invoke-RestMethod "http://127.0.0.1:18743/v1/jobs/$JobId" -Headers $headers -TimeoutSec 3
    if ($job.state -eq 'failed' -or $job.error) { throw "Job failed: $($job.error)" }
    if ($job.state -ne 'completed') { return $false }
    if ($job.exit -ne 0 -or $job.stdout -notmatch [Regex]::Escape($Marker)) { throw 'Durable job exit/output mismatch' }
    $job | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $Work "$Marker.json")
    $true
  } "completed command $Marker"
}
'native-windows-test' | Set-Content -NoNewline (Join-Path $Work 'mcp.token')
'native-windows-admin' | Set-Content -NoNewline (Join-Path $Work 'admin.token')
$env:AI_RELAY_MCP_TOKEN_FILE = Join-Path $Work 'mcp.token'
$env:AI_RELAY_MCP_ADMIN_TOKEN_FILE = Join-Path $Work 'admin.token'
foreach ($token in @('mcp.token','admin.token')) {
  $path = Join-Path $Work $token
  Protect-NativeFile $path
}
$headers = @{Authorization='Bearer native-windows-test'}
$gw = $null; $ag = $null
try {
  $gw = Start-Gateway
  Wait-Health
  $enroll = Invoke-RestMethod -Method Put -Uri http://127.0.0.1:18743/v1/enroll -Headers @{ Authorization = 'Bearer native-windows-admin' } -TimeoutSec 5
  $enroll.token | Set-Content -NoNewline (Join-Path $Work 'enroll.token')
  Protect-NativeFile (Join-Path $Work 'enroll.token')
  $ag = Start-Agent
  Wait-Gate {
    if ($ag.HasExited) { throw 'Agent exited before enrollment' }
    try {
      $candidate = Get-Content -LiteralPath (Join-Path $Work 'agent.cred') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
      [bool]($candidate.device_id -and $candidate.secret)
    } catch { $false }
  } 'complete agent enrollment credential'
  $cred = Get-Content (Join-Path $Work 'agent.cred') | ConvertFrom-Json
  Remove-Item (Join-Path $Work 'enroll.token')
  $jobId = Submit-Command 'native-windows-ok'
  Assert-Job $jobId 'native-windows-ok'
  Stop-Process -Id $ag.Id -Force; $ag.WaitForExit()
  $queued = Submit-Command 'native-windows-reconnect-ok'
  $ag = Start-Agent
  Assert-Job $queued 'native-windows-reconnect-ok'
  Stop-Process -Id $gw.Id -Force; $gw.WaitForExit()
  $gw = Start-Gateway
  Wait-Health
  Assert-Job $jobId 'native-windows-ok'
  Assert-Job (Submit-Command 'native-windows-persistence-ok') 'native-windows-persistence-ok'
  & $agent -telemetry-off -telemetry-file (Join-Path $Work 'telemetry.json')
  if ($LASTEXITCODE -ne 0) { throw 'Telemetry opt-out failed' }
  $telemetry = & $agent -telemetry-status -telemetry-file (Join-Path $Work 'telemetry.json')
  if ($LASTEXITCODE -ne 0 -or ($telemetry -join ' ') -notmatch 'enabled=false') { throw 'Telemetry opt-out status mismatch' }
  $report = & $agent -report-preview | ConvertFrom-Json
  if ($LASTEXITCODE -ne 0 -or $report.platform -ne 'windows') { throw 'Diagnostic platform mismatch' }
  'native Windows functional/reconnect/persistence/telemetry/diagnostics gates: PASS' | Tee-Object -FilePath (Join-Path $Work 'RESULT.txt')
  Write-Output "Evidence directory: $Work"
} finally {
  if ($ag) { Stop-Process -Id $ag.Id -Force -ErrorAction SilentlyContinue }
  if ($gw) { Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue }
}
