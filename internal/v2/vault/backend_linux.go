//go:build linux

package vault

import "context"

// OpenDefault selects Secret Service when its no-write capability probe
// succeeds, otherwise opens the encrypted-file fallback. The caller retains
// explicit control of fallback paths and can use OpenSecretService directly
// when native storage is mandatory.
func OpenDefault(ctx context.Context, path, keyPath string) (Store, error) {
	if err := validateActiveOpenContext(ctx); err != nil {
		return nil, err
	}
	return chooseStoreWithContext(
		ctx,
		func() (Store, error) { return OpenFile(path, keyPath) },
		func() (Store, error) { return OpenSecretService(ctx) },
	)
}
