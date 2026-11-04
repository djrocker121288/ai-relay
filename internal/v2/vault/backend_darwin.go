//go:build darwin

package vault

import "context"

// OpenDefault selects the macOS login Keychain when the Security framework is
// available. With cgo disabled OpenKeychain returns ErrUnavailable and the
// encrypted-file fallback is selected.
func OpenDefault(ctx context.Context, path, keyPath string) (Store, error) {
	if err := validateActiveOpenContext(ctx); err != nil {
		return nil, err
	}
	return chooseStoreWithContext(
		ctx,
		func() (Store, error) { return OpenFile(path, keyPath) },
		func() (Store, error) {
			store, err := OpenKeychain()
			if err != nil {
				return nil, err
			}
			return store, nil
		},
	)
}
