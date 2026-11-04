//go:build windows

package vault

import "context"

// OpenNative selects the current user's Windows Credential Manager without
// permitting the encrypted-file fallback. It is intended for supervisor
// verification and callers whose policy requires an OS-backed store.
func OpenNative(ctx context.Context) (Store, error) {
	return openNativeWithContext(ctx, func() (Store, error) {
		return OpenCredentialManager(), nil
	})
}
