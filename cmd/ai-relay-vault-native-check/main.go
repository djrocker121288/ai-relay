package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ai-relay/ai-relay/internal/v2/vault"
)

const (
	defaultNativeVerificationTimeout = 45 * time.Second
	maxNativeVerificationTimeout     = 5 * time.Minute
	maxEvidenceFileBytes             = 4 << 10
)

func main() {
	name := flag.String("name", "", "unique non-secret native test item name")
	evidenceFile := flag.String("evidence-file", "", "bounded retained native verification JSON to validate offline")
	timeout := flag.Duration("timeout", defaultNativeVerificationTimeout, "maximum native verification setup time (up to 5m)")
	flag.Parse()
	if strings.TrimSpace(*evidenceFile) != "" {
		if *name != "" {
			fmt.Fprintln(os.Stderr, "-name and -evidence-file cannot be used together")
			os.Exit(2)
		}
		result, err := readEvidence(*evidenceFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native verification evidence is invalid")
			os.Exit(1)
		}
		printResult(result)
		return
	}
	if *name == "" {
		fmt.Fprintln(os.Stderr, "-name is required unless -evidence-file is supplied; use a unique non-secret supervisor/ item name")
		os.Exit(2)
	}
	if err := vault.ValidateNativeVerificationName(*name); err != nil {
		fmt.Fprintf(os.Stderr, "-name is invalid: %v\n", err)
		os.Exit(2)
	}
	if err := validateTimeout(*timeout); err != nil {
		fmt.Fprintf(os.Stderr, "-timeout is invalid: %v\n", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := verify(ctx, *name)
	printResult(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printResult(result vault.NativeVerificationResult) {
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, "native verification evidence encoding failed")
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}

func readEvidence(path string) (vault.NativeVerificationResult, error) {
	if strings.TrimSpace(path) == "" {
		return vault.NativeVerificationResult{}, errors.New("evidence path is required")
	}
	file, err := openEvidenceFile(path)
	if err != nil {
		return vault.NativeVerificationResult{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxEvidenceFileBytes+1))
	if err != nil {
		return vault.NativeVerificationResult{}, err
	}
	if err := validateEvidenceFileIdentity(path, file); err != nil {
		return vault.NativeVerificationResult{}, err
	}
	if len(data) > maxEvidenceFileBytes {
		return vault.NativeVerificationResult{}, errors.New("evidence exceeds limit")
	}
	return vault.ParseNativeVerificationEvidence(data)
}

// openEvidenceFile keeps offline replay on a regular file supplied by the
// supervisor. The second path check catches a replacement between the initial
// lstat and open; replay remains validation of untrusted evidence, not proof of
// file provenance or a native-session result.
func openEvidenceFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("evidence path is not a regular file")
	}

	file, err := openEvidenceNoFollow(path)
	if err != nil {
		return nil, err
	}
	if err := validateEvidenceFileIdentity(path, file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateEvidenceFileIdentity(path string, file *os.File) error {
	if file == nil {
		return errors.New("evidence file is nil")
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	currentInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !currentInfo.Mode().IsRegular() || !os.SameFile(openedInfo, currentInfo) {
		return errors.New("evidence path changed during read")
	}
	return nil
}

func validateTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("must be positive")
	}
	if timeout > maxNativeVerificationTimeout {
		return fmt.Errorf("must not exceed %s", maxNativeVerificationTimeout)
	}
	return nil
}

var openNative = vault.OpenNative

func verify(ctx context.Context, name string) (vault.NativeVerificationResult, error) {
	if err := vault.ValidateContext(ctx); err != nil {
		return vault.NativeVerificationResult{Name: name}, fmt.Errorf("native verification context: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return vault.NativeVerificationResult{Name: name}, fmt.Errorf("native verification context: %w", err)
	}
	if err := vault.ValidateNativeVerificationName(name); err != nil {
		return vault.NativeVerificationResult{Name: name}, fmt.Errorf("validate native item name: %w", err)
	}
	store, err := openNative(ctx)
	if err != nil {
		return vault.NativeVerificationResult{Name: name}, fmt.Errorf("open native vault: %w", vault.RedactNativeVerificationError("open", err))
	}
	// Native setup may finish after the caller's deadline or cancellation. Do
	// not inspect the returned backend boundary or report a misleading shape
	// error when the supervisor has already withdrawn the verification run.
	if err := vault.ValidateContext(ctx); err != nil {
		return vault.NativeVerificationResult{Name: name}, fmt.Errorf("native verification context: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return vault.NativeVerificationResult{Name: name}, fmt.Errorf("native verification context: %w", err)
	}
	cleanup, ok := store.(vault.NativeCleanup)
	if !ok {
		return vault.NativeVerificationResult{Name: name}, fmt.Errorf("native vault does not expose supervisor cleanup")
	}
	return vault.VerifyNativeLifecycleContext(ctx, store, cleanup, name)
}
