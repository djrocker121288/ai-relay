//go:build !linux && !windows && !darwin

package vault

import "context"

// OpenDefault uses the encrypted-file fallback on unsupported platforms.
func OpenDefault(ctx context.Context, path, keyPath string) (Store, error) {
	return openFallbackWithContext(ctx, func() (Store, error) {
		return OpenFile(path, keyPath)
	})
}
