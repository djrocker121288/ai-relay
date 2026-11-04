//go:build windows

package vault

import "context"

// OpenDefault selects the Windows user's Credential Manager. The shared
// selector still validates the native construction boundary; the encrypted
// file remains available through OpenFile as an explicit rollback choice.
func OpenDefault(ctx context.Context, path, keyPath string) (Store, error) {
	if err := validateActiveOpenContext(ctx); err != nil {
		return nil, err
	}
	return chooseStoreWithContext(
		ctx,
		func() (Store, error) { return OpenFile(path, keyPath) },
		func() (Store, error) { return OpenCredentialManager(), nil },
	)
}
