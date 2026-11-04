//go:build darwin

package vault

import "context"

// OpenNative selects the macOS login Keychain without permitting the
// encrypted-file fallback. It is intended for supervisor verification and
// callers whose policy requires an OS-backed store.
func OpenNative(ctx context.Context) (Store, error) {
	return openNativeWithContext(ctx, func() (Store, error) {
		return OpenKeychain()
	})
}
