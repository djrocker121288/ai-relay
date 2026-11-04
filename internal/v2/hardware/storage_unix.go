//go:build !windows

package hardware

import (
	"os"
	"syscall"
)

func detectStorage() (Storage, error) {
	path, err := os.Getwd()
	if err != nil {
		return Storage{}, err
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return Storage{}, err
	}
	return Storage{Path: path, TotalBytes: stat.Blocks * uint64(stat.Bsize), AvailableBytes: stat.Bavail * uint64(stat.Bsize)}, nil
}
