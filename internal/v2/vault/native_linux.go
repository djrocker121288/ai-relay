//go:build linux

package vault

import "context"

// OpenNative selects Secret Service without permitting the encrypted-file
// fallback. It is intended for supervisor verification and callers whose
// policy requires an OS-backed store.
func OpenNative(ctx context.Context) (Store, error) {
	return openNativeWithContext(ctx, func() (Store, error) {
		return OpenSecretService(ctx)
	})
}
