# ARPL Windows service scaffold. Register with a service wrapper such as
# WinSW/NSSM after installing the reviewed binary and ACL-protected state dir.
$Binary = 'C:\Program Files\AI Relay\ai-relay-arpl.exe'
$Args = 'connect -addr SERVER3:9443 -key-file C:\ProgramData\AI Relay\arpl\identity.json -session-file C:\ProgramData\AI Relay\arpl\session.json -peer-key ENROLLED_SERVER_PUBLIC_KEY -ca-file C:\ProgramData\AI Relay\arpl\ca.pem'
Write-Host "Install a LocalService wrapper for: $Binary $Args"
Write-Host 'Grant only the service SID access to C:\ProgramData\AI Relay\arpl and keep SSH fallback enabled.'
