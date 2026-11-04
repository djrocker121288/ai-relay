# ARPL installers

The installers in this directory consume a candidate archive and its
`SHA256SUMS`; they verify the archive before replacing a binary. Linux/macOS
use the native shell path, Windows uses the PowerShell user installer, and
Android uses the companion project in `deploy/android` or the Termux fallback
when an APK build is unavailable.

Installation is host/client/both-neutral. The Linux, macOS, and Termux shell
entry points and the Windows PowerShell entry point initialize an identity and
settings file, consume an optional signed one-time enrollment payload, and run
`settings apply` into a platform-specific service directory. Native service
activation is an explicit operator step (`ARPL_SERVICE_ACTIVATE=1` for the
shell path); no installer replaces a production service. No installer transfers
a private key or embeds a release signing key, and no `.pkg` or `.msi` artifact
is claimed.
