package arpl

import (
	"context"
)

type terminalSession interface {
	Write([]byte) (int, error)
	Resize(rows, cols uint16) error
	Close() error
	Run(func([]byte) error) (int, error)
}

func normalizeTerminalSize(rows, cols int) (uint16, uint16) {
	if rows <= 0 || rows > 1000 {
		rows = 24
	}
	if cols <= 0 || cols > 2000 {
		cols = 80
	}
	return uint16(rows), uint16(cols)
}

func terminalCommandContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
