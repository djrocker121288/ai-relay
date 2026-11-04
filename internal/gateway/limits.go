package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxCommandBody = 256 * 1024

// JSON can escape each output byte as six bytes. Two 1MiB streams fit here.
const maxResultBody = 16 * 1024 * 1024
const maxStoredOutput = 1024 * 1024

func readRequestBody(r *http.Request) ([]byte, error) {
	limit := maxCommandBody
	if r.URL.Path == "/v1/agent/result" {
		limit = maxResultBody
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("request exceeds %d bytes", limit)
	}
	return data, nil
}
func decodeRequest(r *http.Request, v any) error {
	data, err := readRequestBody(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
func storedOutput(value string) (string, bool) {
	if len(value) > maxStoredOutput {
		return strings.Clone(value[len(value)-maxStoredOutput:]), true
	}
	return value, false
}
