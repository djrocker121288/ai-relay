//go:build windows

package vault

import "os"

// syncVaultDirectory is a variable shared with the portable atomic-write
// helper. Windows rename durability is delegated to the filesystem API.
var syncVaultDirectory = syncVaultDirectoryImpl

// Portable directory handles cannot be synchronised with os.File.Sync there;
// native filesystem/ACL durability remains part of the supervisor gate.
func syncVaultDirectoryImpl(string, *os.File) error { return nil }
