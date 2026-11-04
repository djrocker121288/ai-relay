# Installation

The public release has one installer logic path and several launchers. All
launchers verify the matching platform archive against `SHA256SUMS`, stage
binaries/configuration, initialize ARPL only when absent, and report local
enrollment state without claiming connectivity.

## Desktop

1. Download the platform setup bundle and `SHA256SUMS` from the same release.
2. Verify the checksum before extracting.
3. Launch the platform entry point:
   - Linux: execute the matching `.run`.
   - macOS: unzip and open the matching `AI-Relay-ARPL-Setup.app`; native release builds may also provide unsigned `.pkg` and `.dmg` wrappers until Developer ID signing/notarization is configured.
   - Windows: unzip and double-click `AI-Relay-ARPL-Setup.exe`.
4. Review the result. Without a protected AI Relay credential the truthful
   result is `ENROLLMENT REQUIRED`.
5. Use `--activate` only after reviewing generated settings/service files.

The Windows executable starts PowerShell itself with a noninteractive,
no-profile invocation. It does not install PowerShell, bypass UAC, or silently
create an elevated task.

## Enrollment

An existing credential is supplied by path:

~~~sh
./AI-Relay-ARPL-Setup_2.1.2_linux_amd64.run \
  --credential-file /secure/agent.cred
~~~

For new enrollment, use a single-use token file with an explicit gateway:

~~~sh
chmod 600 /secure/one-use-enroll.token
./AI-Relay-ARPL-Setup_2.1.2_linux_amd64.run \
  --gateway https://relay.example.invalid \
  --enroll-token-file /secure/one-use-enroll.token
~~~

The token value must not be placed in shell history, a process argument, an
environment variable, a URL, or a log. ARPL signed enrollment payloads are
also passed by protected file path.

## Roles

`endpoint` stages agent + ARPL. `full` and `server` additionally stage
the loopback gateway on desktop operating systems. Android/Termux supports
endpoint only. Native activation is explicit and platform-owned.

## Status, doctor, and repair

~~~sh
./AI-Relay-ARPL-Setup_2.1.2_linux_amd64.run status
./AI-Relay-ARPL-Setup_2.1.2_linux_amd64.run doctor
./AI-Relay-ARPL-Setup_2.1.2_linux_amd64.run repair
~~~

These checks describe local staging/configuration. A credential file does not
prove that a relay connection is live.

## Termux and Android

Unzip `AI-Relay-ARPL-Termux-Bootstrap_2.1.2_android_arm64.zip` inside
Termux and run `./AI-Relay-ARPL-Termux-Bootstrap.sh`. It stages the arm64
endpoint package in Termux user space. It does not install a native Android
APK, request root, bypass Android permission prompts, or claim Termux:Boot
availability. The optional companion source in `deploy/android/` uses
Android's foreground-service and battery-optimization permission flows.

## Uninstall checklist

1. Run `status` and record only the non-secret paths.
2. Stop explicitly activated user services/tasks using the host's normal UI or
   service manager.
3. Remove the installed prefix and generated service entries after review.
4. Remove AI Relay config/state only if the operator intends to remove local
   identity and peer history.
5. Preserve or securely destroy credentials and private keys according to the
   operator's retention policy.

The installer does not provide a destructive uninstall command.

