//go:build !darwin || !cgo

package vault

// OpenKeychain fails closed when the macOS Security framework is unavailable.
// Callers must explicitly select the encrypted-file fallback.
func OpenKeychain() (*Keychain, error) { return nil, ErrUnavailable }
