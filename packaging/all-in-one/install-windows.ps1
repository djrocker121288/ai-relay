[CmdletBinding()]
param(
  [string]$SourceDir = $env:AI_RELAY_SOURCE_DIR,
  [string]$BaseUrl = $env:AI_RELAY_BASE_URL,
  [string]$Version = $(if ($env:AI_RELAY_VERSION) { $env:AI_RELAY_VERSION } else { '2.0.0' }),
  [ValidateSet('endpoint','full','server')][string]$Role = $(if ($env:AI_RELAY_ROLE) { $env:AI_RELAY_ROLE } else { 'endpoint' }),
  [string]$Prefix = $(if ($env:AI_RELAY_PREFIX) { $env:AI_RELAY_PREFIX } else { (Join-Path $env:LOCALAPPDATA 'AI Relay') }),
  [string]$ConfigDir = $(if ($env:AI_RELAY_CONFIG_DIR) { $env:AI_RELAY_CONFIG_DIR } else { (Join-Path $env:APPDATA 'ai-relay') }),
  [string]$StateDir = $(if ($env:AI_RELAY_STATE_DIR) { $env:AI_RELAY_STATE_DIR } else { (Join-Path $env:LOCALAPPDATA 'AI Relaystate') }),
  [string]$Gateway = $(if ($env:AI_RELAY_GATEWAY) { $env:AI_RELAY_GATEWAY } else { 'http://127.0.0.1:8743' }),
  [string]$CredentialFile = $env:AI_RELAY_CREDENTIAL_FILE,
  [string]$EnrollTokenFile = $env:AI_RELAY_ENROLL_TOKEN_FILE,
  [string]$EnrollmentPayloadFile = $env:ARPL_ENROLLMENT_PAYLOAD_FILE,
  [string]$PeerName = $(if ($env:AI_RELAY_PEER_NAME) { $env:AI_RELAY_PEER_NAME } else { 'enrolled-peer' }),
  [switch]$Activate,
  [switch]$Status,
  [switch]$Doctor,
  [switch]$Repair
)
$ErrorActionPreference = 'Stop'
if ($Role -eq 'server') { $Role = 'full' }
$binDir = Join-Path $Prefix 'bin'
$arplDir = Join-Path $ConfigDir 'arpl'
$servicesDir = Join-Path $Prefix 'shareai-relayarpl'
$arpl = Join-Path $binDir 'ai-relay-arpl.exe'
$agent = Join-Path $binDir 'ai-relay-agent.exe'
$gatewayBin = Join-Path $binDir 'ai-relay-gateway.exe'
$identity = Join-Path $arplDir 'identity.json'
$settings = Join-Path $arplDir 'settings.json'
$credential = Join-Path $ConfigDir 'agent.cred'

function Show-Status {
  Write-Output 'AI Relay + ARPL all-in-one status'
  Write-Output "platform: windows/$([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
  Write-Output "prefix: $Prefix"
  if (Test-Path $agent) { Write-Output 'agent: staged' } else { Write-Output 'agent: missing' }
  if (Test-Path $credential) { Write-Output 'agent enrollment: credential configured; connectivity not tested' }
  else { Write-Output 'agent enrollment: ENROLLMENT REQUIRED (staged; agent is not connected)' }
  if ($Role -eq 'full' -and (Test-Path $gatewayBin)) { Write-Output 'gateway: staged; loopback activation is operator-controlled' }
  else { Write-Output 'gateway: not installed for endpoint role' }
  if (Test-Path $arpl) { & $arpl status -key-file $identity 2>$null } else { Write-Output 'ARPL: not initialized' }
}
if ($Status -or $Doctor) {
  Show-Status
  if ($Doctor -and (Test-Path $arpl) -and (Test-Path $settings)) { & $arpl doctor --settings-file $settings; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
  exit 0
}

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
switch ($arch) { 'x64' { $archName = 'amd64' } 'arm64' { $archName = 'arm64' } default { throw "Unsupported Windows architecture: $arch" } }
$pkg = "ai-relay-all-in-one_${Version}_windows_${archName}.zip"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('ai-relay-aio-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $pkgPath = Join-Path $tmp $pkg; $sumPath = Join-Path $tmp 'SHA256SUMS'
  if ($BaseUrl) {
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$pkg" -OutFile $pkgPath
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/SHA256SUMS" -OutFile $sumPath
  } else {
    if (-not $SourceDir) { $SourceDir = $PSScriptRoot }
    if (-not (Test-Path (Join-Path $SourceDir $pkg))) { throw "Package not found: $(Join-Path $SourceDir $pkg)" }
    Copy-Item (Join-Path $SourceDir $pkg) $pkgPath
    Copy-Item (Join-Path $SourceDir 'SHA256SUMS') $sumPath
  }
  $line = Get-Content $sumPath | Where-Object { $_ -match ([regex]::Escape($pkg) + '$') } | Select-Object -First 1
  if (-not $line) { throw "Release checksum missing for $pkg" }
  $expected = ($line -split 's+')[0].ToLowerInvariant()
  $actual = (Get-FileHash -Algorithm SHA256 $pkgPath).Hash.ToLowerInvariant()
  if ($expected -ne $actual) { throw "SHA-256 verification failed for $pkg" }
  $unpack = Join-Path $tmp 'unpack'; Expand-Archive -Force $pkgPath $unpack
  foreach ($name in @('ai-relay-arpl.exe','ai-relay-agent.exe')) {
    if (-not (Test-Path (Join-Path $unpack "bin$name"))) { throw "Package is missing $name" }
  }
  if ($Role -eq 'full' -and -not (Test-Path (Join-Path $unpack 'binai-relay-gateway.exe'))) { throw 'Package is missing gateway' }
  New-Item -ItemType Directory -Force -Path $binDir,$arplDir,$StateDir,$servicesDir | Out-Null
  Copy-Item -Force (Join-Path $unpack 'binai-relay-arpl.exe') $arpl
  Copy-Item -Force (Join-Path $unpack 'binai-relay-agent.exe') $agent
  if ($Role -eq 'full') { Copy-Item -Force (Join-Path $unpack 'binai-relay-gateway.exe') $gatewayBin }

  if ($CredentialFile) {
    if (-not (Test-Path $CredentialFile -PathType Leaf)) { throw 'Credential must be a regular file.' }
    Copy-Item -Force $CredentialFile $credential
  }
  if (Test-Path $credential) {
    $null = Get-Content -Raw -LiteralPath $credential | ConvertFrom-Json
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & (Join-Path $env:SystemRoot 'System32icacls.exe') $credential '/inheritance:r' '/grant:r' "${user}:F" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to protect credential ACL.' }
  }
  if (-not (Test-Path $identity)) { & $arpl key rotate -key-file $identity | Out-Null }
  if (-not (Test-Path $settings)) { & $arpl settings init --file $settings | Out-Null }
  if ($EnrollTokenFile -and -not (Test-Path $credential)) {
    if (-not $env:AI_RELAY_GATEWAY -and -not $PSBoundParameters.ContainsKey('Gateway')) { throw 'A gateway URL is required with -EnrollTokenFile.' }
    if (-not (Test-Path $EnrollTokenFile -PathType Leaf)) { throw 'Enrollment token must be a regular file.' }
    & $agent -gateway $Gateway -credential-file $credential -enroll-token-file $EnrollTokenFile -enroll-only
    if ($LASTEXITCODE -ne 0) { throw 'AI Relay enrollment failed.' }
  }
  if ($EnrollmentPayloadFile) {
    if (-not (Test-Path $EnrollmentPayloadFile -PathType Leaf)) { throw 'ARPL enrollment payload must be a regular file.' }
    & $arpl enroll consume -payload-file $EnrollmentPayloadFile -settings-file $settings -name $PeerName -key-file $identity
    if ($LASTEXITCODE -ne 0) { throw 'ARPL enrollment payload was rejected.' }
  }
  if ($Role -eq 'full' -and -not (Test-Path (Join-Path $ConfigDir 'gateway.env'))) {
    Set-Content -NoNewline -Encoding UTF8 -Path (Join-Path $ConfigDir 'gateway.env') -Value '# Add protected token-file paths when configuring MCP.'
  }
  # The output directory is staging-only.  Explicit activation below invokes
  # ARPL again in native Windows mode so its Scheduled Tasks are registered by
  # ARPL's own settings-apply logic.
  $previousArplActivation = [Environment]::GetEnvironmentVariable('ARPL_SERVICE_ACTIVATE', 'Process')
  try {
    $env:ARPL_SERVICE_ACTIVATE = '0'
    & $arpl settings apply --file $settings --platform windows --output-dir $servicesDir | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'ARPL service scaffolding failed.' }
  } finally {
    if ($null -eq $previousArplActivation) { Remove-Item Env:ARPL_SERVICE_ACTIVATE -ErrorAction SilentlyContinue }
    else { $env:ARPL_SERVICE_ACTIVATE = $previousArplActivation }
  }

  if ($Activate) {
    & $arpl settings apply --file $settings --platform windows | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'ARPL native activation failed.' }
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($Role -eq 'full') {
      $a = New-ScheduledTaskAction -Execute $gatewayBin -Argument ('-listen 127.0.0.1:8743 -state "{0}"' -f (Join-Path $StateDir 'gateway')) -WorkingDirectory $Prefix
      $t = New-ScheduledTaskTrigger -AtLogOn
      $p = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
      Register-ScheduledTask -TaskName 'AI Relay Gateway' -Action $a -Trigger $t -Principal $p -Force | Out-Null
    }
    if (Test-Path $credential) {
      $a = New-ScheduledTaskAction -Execute $agent -Argument ('-gateway "{0}" -credential-file "{1}"' -f $Gateway,$credential) -WorkingDirectory $Prefix
      $t = New-ScheduledTaskTrigger -AtLogOn
      $p = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
      Register-ScheduledTask -TaskName 'AI Relay Agent' -Action $a -Trigger $t -Principal $p -Force | Out-Null
    } else { Write-Output 'ENROLLMENT REQUIRED: agent persistence was staged but not activated.' }
    Write-Output 'Windows activation uses current-user Scheduled Tasks; no UAC bypass was used.'
  }
  Write-Output "Installed AI Relay + ARPL all-in-one $Version for windows/$archName."
  Write-Output "Binaries: $binDir"
  Write-Output "ARPL settings: $settings"
  Write-Output "Service scaffolding: $servicesDir"
  if (Test-Path $credential) { Write-Output 'Agent enrollment: credential configured; connectivity was not tested.' }
  else { Write-Output 'ENROLLMENT REQUIRED: agent is staged and not connected.' }
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
