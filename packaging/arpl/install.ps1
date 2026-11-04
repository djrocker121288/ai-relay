param(
  [string]$SourceDir = $env:ARPL_SOURCE_DIR,
  [string]$BaseUrl = $env:ARPL_BASE_URL,
  [string]$InstallDir = "$env:LOCALAPPDATA\AI Relay\ARPL\bin",
	[string]$Version = "0.2.0",
	[string]$EnrollmentPayload = $env:ARPL_ENROLLMENT_PAYLOAD,
	[string]$PeerName = "enrolled-peer"
)

$ErrorActionPreference = "Stop"
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
switch ($arch) {
  "x64"   { $archName = "amd64" }
  "arm64" { $archName = "arm64" }
  default { throw "Unsupported Windows architecture: $arch" }
}

$pkg = "ai-relay-arpl_${Version}_windows_${archName}.zip"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("arpl-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $pkgPath = Join-Path $tmp $pkg
  $sumPath = Join-Path $tmp "SHA256SUMS"
  if ($SourceDir) {
    Copy-Item (Join-Path $SourceDir $pkg) $pkgPath
    Copy-Item (Join-Path $SourceDir "SHA256SUMS") $sumPath
  } elseif ($BaseUrl) {
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$pkg" -OutFile $pkgPath
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/SHA256SUMS" -OutFile $sumPath
  } else {
    $local = Join-Path $PSScriptRoot "dist"
    if (-not (Test-Path (Join-Path $local $pkg))) {
      $tryPath = Join-Path $PSScriptRoot "..\..\dist\arpl-v$Version"
      if (Test-Path $tryPath) { $local = (Resolve-Path $tryPath).Path }
    }
    if (-not (Test-Path (Join-Path $local $pkg))) {
      throw "No package source found. Use -SourceDir or -BaseUrl."
    }
    Copy-Item (Join-Path $local $pkg) $pkgPath
    Copy-Item (Join-Path $local "SHA256SUMS") $sumPath
  }

  $line = Get-Content $sumPath | Where-Object { $_ -match ([regex]::Escape($pkg) + '$') } | Select-Object -First 1
  if (-not $line) { throw "Package missing from SHA256SUMS" }
  $expected = ($line -split '\s+')[0].ToLowerInvariant()
  $actual = (Get-FileHash -Algorithm SHA256 $pkgPath).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "SHA-256 verification failed" }

  $unpack = Join-Path $tmp "unpack"
  Expand-Archive -Force $pkgPath $unpack
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -Force (Join-Path $unpack "ai-relay-arpl.exe") (Join-Path $InstallDir "ai-relay-arpl.exe")

  $wrapper = "@echo off`r`n`"%~dp0ai-relay-arpl.exe`" %*`r`n"
  Set-Content -Encoding Ascii -NoNewline -Path (Join-Path $InstallDir "arpl.cmd") -Value $wrapper

  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $parts = @($userPath -split ';' | Where-Object { $_ })
  if ($parts -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", (($parts + $InstallDir) -join ';'), "User")
  }

	$config = Join-Path $env:APPDATA "ai-relay\arpl"
  New-Item -ItemType Directory -Force -Path $config | Out-Null
  $identity = Join-Path $config "identity.json"
	if (-not (Test-Path $identity)) {
    & (Join-Path $InstallDir "ai-relay-arpl.exe") key rotate -key-file $identity
    if ($LASTEXITCODE -ne 0) { throw "Identity creation failed" }
	}
	$settings = Join-Path $config "settings.json"
	if (-not (Test-Path $settings)) {
		& (Join-Path $InstallDir "ai-relay-arpl.exe") settings init --file $settings
		if ($LASTEXITCODE -ne 0) { throw "ARPL settings initialization failed" }
	}
	if ($EnrollmentPayload) {
		& (Join-Path $InstallDir "ai-relay-arpl.exe") enroll consume --payload $EnrollmentPayload --settings-file $settings --name $PeerName --key-file $identity
		if ($LASTEXITCODE -ne 0) { throw "ARPL enrollment failed" }
	}
	$services = Join-Path $InstallDir "services"
	New-Item -ItemType Directory -Force -Path $services | Out-Null
	& (Join-Path $InstallDir "ai-relay-arpl.exe") settings apply --file $settings --platform windows --output-dir $services
	if ($LASTEXITCODE -ne 0) { throw "ARPL settings apply failed" }

  Write-Host "Installed: $InstallDir\ai-relay-arpl.exe"
	Write-Host "Command:   arpl"
	Write-Host "Settings:  $settings"
	Write-Host "Services:  $services"
  & (Join-Path $InstallDir "ai-relay-arpl.exe") status -key-file $identity
  Write-Host "Open a new PowerShell window so the updated PATH is loaded."
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
