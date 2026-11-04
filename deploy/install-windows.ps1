[CmdletBinding()]
param(
  [string]$Gateway,
  [string]$CredentialFile,
  [string]$AgentPath = (Join-Path $PSScriptRoot 'ai-relay-agent.exe'),
  [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'AI Relay'),
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$TaskName = 'AI-Relay-Agent'
if ($Uninstall) {
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($task) { Stop-ScheduledTask -TaskName $TaskName; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
  Write-Output 'AI Relay logon task removed; credentials and installed files preserved.'
  return
}
if (!$Gateway -or !$CredentialFile) { throw 'Specify -Gateway and an existing enrolled -CredentialFile.' }
$uri = [Uri]$Gateway
if (!$uri.IsAbsoluteUri -or $uri.Scheme -notin @('http','https')) { throw 'Gateway must be an absolute HTTP(S) URL.' }
if ($uri.Scheme -eq 'http' -and !$uri.IsLoopback) { throw 'Remote gateways require HTTPS.' }
if (Get-Service -Name $TaskName -ErrorAction SilentlyContinue) { throw 'A legacy AI-Relay-Agent service exists. Stop and remove it before installing a logon task.' }
if (!(Test-Path -LiteralPath $AgentPath -PathType Leaf)) { throw 'Agent binary missing: specify -AgentPath.' }
$credential = Get-Content -LiteralPath $CredentialFile -Raw | ConvertFrom-Json
if (!$credential.device_id -or !$credential.secret) { throw 'Credential file must contain an enrolled device_id and secret.' }
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
$Prefix = (Resolve-Path -LiteralPath $Prefix).Path
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
function Set-RelayAcl {
  param([string]$Path, [string[]]$Grants)
  $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
  & $icacls $Path '/inheritance:r' '/grant:r' $Grants | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Failed to protect ACL on $Path (icacls exit $LASTEXITCODE)." }
}
# Protect installed executable, credentials and logs from other local users.
Set-RelayAcl -Path $Prefix -Grants @("${user}:(OI)(CI)F", '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) { Stop-ScheduledTask -TaskName $TaskName }
$installedAgent = Join-Path $Prefix 'ai-relay-agent.exe'
$installedCredential = Join-Path $Prefix 'agent.cred'
if ((Resolve-Path -LiteralPath $AgentPath).Path -ne $installedAgent) { Copy-Item -LiteralPath $AgentPath -Destination $installedAgent -Force }
if ((Resolve-Path -LiteralPath $CredentialFile).Path -ne $installedCredential) { Copy-Item -LiteralPath $CredentialFile -Destination $installedCredential -Force }
Set-RelayAcl -Path $installedCredential -Grants @("${user}:F", '*S-1-5-18:F', '*S-1-5-32-544:F')
$gatewayBase = $uri.AbsoluteUri.TrimEnd('/')
$arguments = '-gateway "{0}" -credential-file "{1}"' -f $gatewayBase, $installedCredential
$action = New-ScheduledTaskAction -Execute $installedAgent -Argument $arguments -WorkingDirectory $Prefix
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
if ((Get-ScheduledTask -TaskName $TaskName).State -ne 'Running') { throw 'Installed task exited; verify credentials and gateway connectivity.' }
Stop-ScheduledTask -TaskName $TaskName
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
if ((Get-ScheduledTask -TaskName $TaskName).State -ne 'Running') { throw 'Task restart failed.' }
Write-Output 'AI Relay user logon task installed and restart verified. It runs while this user is logged in.'
Write-Output 'Emergency stop: Stop-ScheduledTask -TaskName AI-Relay-Agent. Uninstall: rerun this script -Uninstall.'
