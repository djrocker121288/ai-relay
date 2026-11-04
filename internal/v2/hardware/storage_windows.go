//go:build windows

package hardware

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func detectStorage() (Storage, error) {
	path, err := os.Getwd()
	if err != nil {
		return Storage{}, err
	}
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$d=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($pwd.Path)); $d.TotalSize; $d.AvailableFreeSpace").Output()
	if err != nil {
		return Storage{}, err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return Storage{}, strconv.ErrSyntax
	}
	total, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return Storage{}, err
	}
	free, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return Storage{}, err
	}
	return Storage{Path: path, TotalBytes: total, AvailableBytes: free}, nil
}
