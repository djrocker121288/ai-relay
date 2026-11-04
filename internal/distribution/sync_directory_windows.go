//go:build windows

package distribution

// Windows does not support portable directory-handle synchronization through
// os.File.Sync. Rename durability is delegated to the native filesystem API;
// native installer evidence remains a supervisor-host gate.
var syncUpdateDirectory = syncUpdateDirectoryImpl

func syncUpdateDirectoryImpl(string) error { return nil }
