package vault

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOpenNativeRejectsNilContextBeforePlatformAccess(t *testing.T) {
	if _, err := OpenNative(nil); err == nil || !strings.Contains(err.Error(), "open context is nil") {
		t.Fatalf("OpenNative(nil) error = %v, want nil-context failure", err)
	}
}

func TestOpenNativeRejectsCanceledContextBeforePlatformAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OpenNative(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenNative(canceled) error = %v, want context.Canceled", err)
	}
}
