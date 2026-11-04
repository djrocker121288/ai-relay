package lifecycle

import "os"

// lifecycleFileReady distinguishes an owned descriptor from a non-nil but
// already-closed *os.File left behind by a malformed in-process integration.
// The live-store guard must not rely on pathname identity after the captured
// ownership descriptor has been closed.
func lifecycleFileReady(f *os.File) bool {
	if f == nil {
		return false
	}
	_, err := f.Stat()
	return err == nil
}

func closeLifecycleLock(f *os.File) error {
	if !lifecycleFileReady(f) {
		return ErrClosed
	}
	if err := releaseLifecycleLock(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
