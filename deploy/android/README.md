# Android AI Relay + ARPL companion

The Android companion provides the native Android foreground-service wrapper
for ARPL. The release build embeds ARM64 Android builds of both
`ai-relay-arpl` and `ai-relay-agent` inside the APK. The companion currently
supervises the ARPL runtime; the AI Relay agent binary is bundled for the
combined distribution but is not silently enrolled or started.

The app:

- prefers the bundled ARPL runtime, with optional operator/Termux paths as
  fallbacks;
- creates app-private ARPL settings and identity on first start;
- owns one foreground-service supervisor process with reconnect/backoff;
- watches Android connectivity and keeps an explicit foreground wake lock while
  the supervisor is enabled;
- restarts at boot only after the user has enabled connectivity;
- exposes Android's normal battery-optimization handoff;
- accepts pasted signed enrollment payloads and `arpl://enroll` deep links;
- writes a pending enrollment payload to an app-private file and passes only
  the file path to `ai-relay-arpl enroll consume --payload-file`;
- never places enrollment material in the native process command line;
- does not request root or bypass Android install, foreground-service,
  notification, battery, or background-execution policy.

The default public ARPL configuration is intentionally **unconfigured for any
public relay**. A GitHub build must not point at a project owner's private
hostname.

## Build

The preferred reproducible build entry point is:

```sh
./scripts/build-android-companion.sh 2.1.0
```

It requires Go, Java 17+, Android SDK 35, and Gradle. The script builds ARM64
Android PIE executables for ARPL and the AI Relay agent, stages them as
extracted native libraries, builds the debug APK, and writes a checksum.

The GitHub release workflow provisions Java/Android SDK/Gradle and publishes
the APK as a separate CI artifact. Local Server 3 builds deliberately do not
claim an APK when that Android toolchain is unavailable.

For Termux-only installs, the all-in-one release still provides
`AI-Relay-ARPL-Termux-Bootstrap_<version>_android_arm64.zip`.

## Release boundary

A debug APK is not a production-signed Android release. Before publishing a
production APK, use an owner-controlled keystore, publish the certificate
fingerprint, test install/upgrade behavior on a real ARM64 Android device, and
verify foreground/boot behavior under the supported Android versions.
