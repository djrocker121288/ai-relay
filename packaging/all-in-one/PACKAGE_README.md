# AI Relay + ARPL all-in-one package

This platform archive contains the AI Relay agent and ARPL. Desktop/server
archives also contain the loopback-only AI Relay gateway. The release
directory contains the single preferred installer interface:

- `install-unix.sh` detects Linux, macOS, and Android/Termux plus amd64/arm64.
- `install-windows.ps1` detects Windows x64 or ARM64.

The installer stages files by default. Use `--role full` (or `-Role full`) to
install the gateway on supported desktop/server platforms, and use activation
only after enrollment and local configuration have been reviewed.

Staging renders ARPL files under the package install scaffold and does not
register native persistence. Explicit desktop activation delegates ARPL
persistence to ARPL's native settings-apply path; Windows registers its
configured Scheduled Tasks, while Linux/macOS use ARPL's own service-manager
logic. Android/Termux remains a manual foreground-supervisor path. An AI Relay
credential is required before the AI Relay agent is activated; ARPL activation
follows its own settings independently.
