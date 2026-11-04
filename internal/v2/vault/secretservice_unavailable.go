//go:build !linux

package vault

import "context"

// OpenSecretService is intentionally unavailable until the platform-native
// backend is implemented and tested on that operating system.
func OpenSecretService(context.Context) (*SecretService, error) { return nil, ErrUnavailable }

type SecretService struct{}
