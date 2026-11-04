//go:build !linux && !windows && !darwin

package vault

import "context"

// OpenNative fails closed on unsupported platforms rather than silently
// selecting the encrypted-file fallback.
func OpenNative(ctx context.Context) (Store, error) {
	return openNativeWithContext(ctx, func() (Store, error) {
		return nil, ErrUnavailable
	})
}
