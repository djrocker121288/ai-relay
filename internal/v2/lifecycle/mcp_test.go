package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func newMCPTestAdapter(t *testing.T, owner string, scopes ...string) (*MCPAdapter, *Store) {
	t.Helper()
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	adapter, err := NewMCPAdapter(store, Principal{ID: owner, Scopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	return adapter, store
}

func buildMCPRequest(t *testing.T, id int, method string, params any) []byte {
	t.Helper()
	request := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		request["params"] = params
	}
	b, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mcpToolRequest(t *testing.T, id int, name string, args any) []byte {
	t.Helper()
	return buildMCPRequest(t, id, "tools/call", map[string]any{"name": name, "arguments": args})
}

func decodeMCPResponse(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestBoundedJSONWriterRejectsNilReceiver(t *testing.T) {
	var writer *boundedJSONWriter

	if written, err := writer.Write([]byte("{}")); written != 0 || !errors.Is(err, ErrMCPResponseTooLarge) {
		t.Fatalf("nil writer result = (%d, %v), want (0, %v)", written, err, ErrMCPResponseTooLarge)
	}
}

func TestMCPAdapterLifecycleFlowBindsOwnerAndScopes(t *testing.T) {
	allScopes := []string{ScopeProjectRead, ScopeProjectWrite, ScopeTaskRead, ScopeTaskWrite, ScopeTaskLease}
	adapter, _ := newMCPTestAdapter(t, "controller-a", allScopes...)

	raw, err := adapter.Handle(buildMCPRequest(t, 1, "initialize", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	response := decodeMCPResponse(t, raw)
	result := response["result"].(map[string]any)
	if result["protocolVersion"] != MCPProtocolVersion {
		t.Fatalf("protocol version = %v", result["protocolVersion"])
	}

	for _, request := range []map[string]any{
		{"name": "lifecycle.project.create", "arguments": map[string]any{"id": "p", "name": "Project"}},
		{"name": "lifecycle.task.create", "arguments": map[string]any{"id": "task", "project_id": "p"}},
	} {
		raw, err = adapter.Handle(mcpToolRequest(t, 2, request["name"].(string), request["arguments"]))
		if err != nil {
			t.Fatal(err)
		}
		if got := decodeMCPResponse(t, raw)["result"].(map[string]any)["isError"]; got != false {
			t.Fatalf("tool %s failed: %v", request["name"], got)
		}
	}

	raw, err = adapter.Handle(mcpToolRequest(t, 3, "lifecycle.task.acquire", map[string]any{"task_id": "task", "ttl_seconds": 30}))
	if err != nil {
		t.Fatal(err)
	}
	tool := decodeMCPResponse(t, raw)["result"].(map[string]any)
	if tool["isError"] != false {
		t.Fatalf("acquire failed: %v", tool)
	}
	structured := tool["structuredContent"].(map[string]any)
	if structured["owner"] != "controller-a" {
		t.Fatalf("lease owner = %v, want bound controller", structured["owner"])
	}
	version := structured["version"].(float64)

	raw, err = adapter.Handle(mcpToolRequest(t, 4, "lifecycle.task.checkpoint", map[string]any{
		"task_id": "task", "version": version, "state": "completed", "payload": "done",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeMCPResponse(t, raw)["result"].(map[string]any)["isError"]; got != false {
		t.Fatalf("checkpoint failed: %v", got)
	}
}

func TestMCPAdapterRejectsOwnerSubstitutionAndScopeExpansion(t *testing.T) {
	writer, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectWrite, ScopeTaskWrite, ScopeTaskLease)
	if _, err := writer.Handle(mcpToolRequest(t, 1, "lifecycle.project.create", map[string]any{"id": "p", "name": "Project"})); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Handle(mcpToolRequest(t, 2, "lifecycle.task.create", map[string]any{"id": "task", "project_id": "p"})); err != nil {
		t.Fatal(err)
	}
	raw, err := writer.Handle(mcpToolRequest(t, 3, "lifecycle.task.acquire", map[string]any{"task_id": "task", "ttl_seconds": 30, "owner": "controller-b"}))
	if err != nil {
		t.Fatal(err)
	}
	tool := decodeMCPResponse(t, raw)["result"].(map[string]any)
	if tool["isError"] != true || !strings.Contains(tool["content"].([]any)[0].(map[string]any)["text"].(string), "unknown field") {
		t.Fatalf("owner substitution result = %#v", tool)
	}

	reader, _ := newMCPTestAdapter(t, "controller-b", ScopeTaskRead)
	raw, err = reader.Handle(mcpToolRequest(t, 4, "lifecycle.project.create", map[string]any{"id": "other", "name": "Other"}))
	if err != nil {
		t.Fatal(err)
	}
	tool = decodeMCPResponse(t, raw)["result"].(map[string]any)
	if tool["isError"] != true || !strings.Contains(tool["content"].([]any)[0].(map[string]any)["text"].(string), "scope is not granted") {
		t.Fatalf("scope denial result = %#v", tool)
	}
}

func TestMCPAdapterRejectsMalformedRequestsAndSideEffectingNotifications(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectWrite)
	for _, request := range [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","extra":true}`),
		[]byte(`{"jsonrpc":"2.0","id":true,"method":"ping"}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","method":"initialize"}`),
	} {
		raw, err := adapter.Handle(request)
		if err != nil {
			t.Fatal(err)
		}
		if got := decodeMCPResponse(t, raw)["error"]; got == nil {
			t.Fatalf("malformed request unexpectedly succeeded: %s", raw)
		}
	}
	raw, err := adapter.Handle([]byte(`{"jsonrpc":"2.0","id":true,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	if response := decodeMCPResponse(t, raw); response["id"] != nil {
		t.Fatalf("invalid request ID was reflected: %#v", response)
	}
	raw, err = adapter.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":null}}`))
	if err != nil {
		t.Fatal(err)
	}
	if result := decodeMCPResponse(t, raw)["result"].(map[string]any); result["isError"] != true {
		t.Fatalf("null arguments unexpectedly succeeded: %v", result)
	}
	raw, err = adapter.Handle([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","id":"q","name":"Project"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if response := decodeMCPResponse(t, raw); response["error"] == nil {
		t.Fatalf("duplicate tool argument unexpectedly succeeded: %v", response)
	}
	raw, err = adapter.Handle(mcpToolRequest(t, 3, "lifecycle.task.create", map[string]any{"project_id": "p"}))
	if err != nil {
		t.Fatal(err)
	}
	if tool := decodeMCPResponse(t, raw)["result"].(map[string]any); tool["isError"] != true || !strings.Contains(tool["content"].([]any)[0].(map[string]any)["text"].(string), "task ID is required") {
		t.Fatalf("missing task ID was not rejected at MCP boundary: %#v", tool)
	}

	notification := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"Project"}}}`)
	raw, err = adapter.Handle(notification)
	if err != nil || raw != nil {
		t.Fatalf("notification response/error = %q/%v", raw, err)
	}
	raw, err = adapter.Handle(mcpToolRequest(t, 3, "lifecycle.project.read", map[string]any{"id": "p"}))
	if err != nil {
		t.Fatal(err)
	}
	tool := decodeMCPResponse(t, raw)["result"].(map[string]any)
	if tool["isError"] != true {
		t.Fatal("side-effecting notification executed")
	}
}

func TestMCPAdapterClassifiesWellFormedInvalidRequestEnvelopes(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	for _, rawRequest := range []string{
		`[]`,
		`null`,
		`{"JSONRPC":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":2,"id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":2}`,
		`{"jsonrpc":"2.0","id":1.5,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1e0,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","unknown":true}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","id":2}`,
	} {
		raw, err := adapter.Handle([]byte(rawRequest))
		if err != nil {
			t.Fatal(err)
		}
		response := decodeMCPResponse(t, raw)
		errorObject, ok := response["error"].(map[string]any)
		if !ok || errorObject["code"] != float64(-32600) {
			t.Fatalf("well-formed invalid request %s = %#v, want JSON-RPC -32600", rawRequest, response)
		}
		if response["id"] != nil {
			t.Fatalf("invalid request %s reflected an ID: %#v", rawRequest, response)
		}
	}

	raw, err := adapter.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":`))
	if err != nil {
		t.Fatal(err)
	}
	response := decodeMCPResponse(t, raw)
	if response["error"].(map[string]any)["code"] != float64(-32700) {
		t.Fatalf("malformed JSON response = %#v, want JSON-RPC -32700", response)
	}
}

func TestMCPAdapterRejectsCaseVariantArgumentAndParameterMembers(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	cases := []struct {
		name       string
		request    string
		jsonRPCErr bool
	}{
		{
			name:       "initialize parameter",
			request:    `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"ProtocolVersion":"2025-06-18","capabilities":{},"clientInfo":{}}}`,
			jsonRPCErr: true,
		},
		{
			name:    "tool argument",
			request: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lifecycle.project.read","arguments":{"ID":"missing"}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := adapter.Handle([]byte(tc.request))
			if err != nil {
				t.Fatal(err)
			}
			response := decodeMCPResponse(t, raw)
			if tc.jsonRPCErr {
				if response["error"] == nil || response["result"] != nil {
					t.Fatalf("case-variant parameter unexpectedly succeeded: %s", raw)
				}
				return
			}
			result, ok := response["result"].(map[string]any)
			if !ok || result["isError"] != true {
				t.Fatalf("case-variant argument unexpectedly succeeded: %#v", response)
			}
		})
	}
}

func TestValidMCPIDRequiresOneCompleteJSONValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{name: "omitted notification", raw: nil, want: true},
		{name: "string", raw: json.RawMessage(`"request"`), want: true},
		{name: "integer", raw: json.RawMessage(`-42`), want: true},
		{name: "trailing value", raw: json.RawMessage(`1 2`), want: false},
		{name: "trailing object", raw: json.RawMessage(`"request" {}`), want: false},
		{name: "fractional number", raw: json.RawMessage(`1.5`), want: false},
		{name: "invalid UTF-8", raw: json.RawMessage([]byte{'"', 0xff, '"'}), want: false},
		{name: "oversized JSON string", raw: json.RawMessage(`"` + strings.Repeat("x", maxMCPRequestBytes) + `"`), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validMCPID(tc.raw); got != tc.want {
				t.Fatalf("validMCPID(%s) = %t, want %t", tc.raw, got, tc.want)
			}
		})
	}
}

func TestMCPScalarHelpersEnforceRequestBound(t *testing.T) {
	oversized := []byte(strings.Repeat("x", maxMCPRequestBytes+1))
	var value any
	if err := decodeSingleJSONValue(oversized, &value); !errors.Is(err, ErrMCPRequestTooLarge) {
		t.Fatalf("oversized direct JSON-value decode error = %v, want ErrMCPRequestTooLarge", err)
	}
	if validMCPIntegerID(json.Number(strings.Repeat("1", maxMCPRequestBytes+1))) {
		t.Fatal("validMCPIntegerID accepted an oversized direct integer")
	}
}

func TestMCPAdapterRejectsUnsupportedInitializeVersion(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":null}}`,
	}
	requests = append(requests, fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"%s"}}`, strings.Repeat("v", maxMCPProtocolVersionBytes+1)))
	for _, rawRequest := range requests {
		raw, err := adapter.Handle([]byte(rawRequest))
		if err != nil {
			t.Fatal(err)
		}
		response := decodeMCPResponse(t, raw)
		if response["error"] == nil {
			t.Fatalf("unsupported initialize request unexpectedly succeeded: %s", raw)
		}
		if response["result"] != nil {
			t.Fatalf("unsupported initialize request returned a result: %s", raw)
		}
	}

	raw, err := adapter.Handle([]byte(`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	response := decodeMCPResponse(t, raw)
	if response["error"] != nil || response["result"].(map[string]any)["protocolVersion"] != MCPProtocolVersion {
		t.Fatalf("supported initialize request was not negotiated: %s", raw)
	}
}

func TestMCPAdapterRejectsMalformedInitializeMetadata(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	for _, rawRequest := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":null,"clientInfo":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":[],"clientInfo":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":null}}`,
		`{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":"client"}}`,
		`{"jsonrpc":"2.0","id":6,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`,
	} {
		raw, err := adapter.Handle([]byte(rawRequest))
		if err != nil {
			t.Fatal(err)
		}
		response := decodeMCPResponse(t, raw)
		if response["error"] == nil || response["result"] != nil {
			t.Fatalf("malformed initialize metadata unexpectedly succeeded: %s", raw)
		}
	}
}

func TestMCPAdapterRejectsMalformedInitializeMetadataWithoutVersion(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	for _, rawRequest := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":null}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"capabilities":[]}}`,
		`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"clientInfo":"client"}}`,
	} {
		raw, err := adapter.Handle([]byte(rawRequest))
		if err != nil {
			t.Fatal(err)
		}
		response := decodeMCPResponse(t, raw)
		if response["error"] == nil || response["result"] != nil {
			t.Fatalf("malformed unversioned initialize metadata unexpectedly succeeded: %s", raw)
		}
	}

	raw, err := adapter.Handle([]byte(`{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"capabilities":{},"clientInfo":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	response := decodeMCPResponse(t, raw)
	if response["error"] != nil || response["result"].(map[string]any)["protocolVersion"] != MCPProtocolVersion {
		t.Fatalf("valid unversioned initialize metadata was not accepted: %s", raw)
	}
}

func TestMCPAdapterRejectsUnsupportedPingAndToolsListParams(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	for _, rawRequest := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping","params":{"future":true}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"next"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":null}`,
	} {
		raw, err := adapter.Handle([]byte(rawRequest))
		if err != nil {
			t.Fatal(err)
		}
		response := decodeMCPResponse(t, raw)
		if response["error"] == nil || response["result"] != nil {
			t.Fatalf("unsupported method parameters unexpectedly succeeded: %s", raw)
		}
		errorObject := response["error"].(map[string]any)
		if errorObject["code"] != float64(-32602) {
			t.Fatalf("error code = %#v, want -32602: %s", errorObject["code"], raw)
		}
	}

	for _, rawRequest := range []string{
		`{"jsonrpc":"2.0","id":5,"method":"ping","params":{}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}`,
	} {
		raw, err := adapter.Handle([]byte(rawRequest))
		if err != nil {
			t.Fatal(err)
		}
		if response := decodeMCPResponse(t, raw); response["error"] != nil {
			t.Fatalf("empty method parameters rejected: %s", raw)
		}
	}
}

func TestMCPAdapterBoundsRequestsAndResponses(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	if _, err := adapter.Handle([]byte(strings.Repeat("x", maxMCPRequestBytes+1))); !errors.Is(err, ErrMCPRequestTooLarge) {
		t.Fatalf("oversized request error = %v", err)
	}
	if _, err := marshalMCPResponse(json.RawMessage("1"), strings.Repeat("x", maxMCPResponseBytes), nil); !errors.Is(err, ErrMCPResponseTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
	if _, err := adapter.Handle(buildMCPRequest(t, 1, "tools/list", nil)); err != nil {
		t.Fatal(err)
	}
}

func TestMarshalBoundedJSONRejectsInvalidLimits(t *testing.T) {
	for _, limit := range []int{-1, 0, maxMCPResponseBytes + 1, int(^uint(0) >> 1)} {
		if _, err := marshalBoundedJSON("value", limit); !errors.Is(err, ErrMCPResponseTooLarge) {
			t.Fatalf("marshalBoundedJSON limit %d error = %v, want ErrMCPResponseTooLarge", limit, err)
		}
	}
}

func TestRejectDuplicateJSONKeysRejectsOversizedInput(t *testing.T) {
	oversized := make([]byte, maxStateBytes+1)
	if err := rejectDuplicateJSONKeys(oversized); !errors.Is(err, errLifecycleJSONTooLarge) {
		t.Fatalf("rejectDuplicateJSONKeys(oversized) = %v, want errLifecycleJSONTooLarge", err)
	}
}

func TestScanJSONValueRejectsUnavailableDecoderAndInvalidDepth(t *testing.T) {
	if err := scanJSONValue(nil); err == nil {
		t.Fatal("scanJSONValue(nil) = nil, want fail-closed parser error")
	}
	for _, depth := range []int{-1, maxMCPJSONDepth + 1} {
		t.Run(fmt.Sprintf("depth-%d", depth), func(t *testing.T) {
			decoder := json.NewDecoder(strings.NewReader(`{}`))
			if err := scanJSONValueAtDepth(decoder, depth); err == nil {
				t.Fatalf("scanJSONValueAtDepth(depth=%d) = nil, want invalid-depth error", depth)
			}
		})
	}
}

func TestDecodeStrictJSONRejectsOversizedInput(t *testing.T) {
	oversized := make([]byte, maxStateBytes+1)
	if err := decodeStrictJSON(oversized, &struct{}{}); !errors.Is(err, errLifecycleJSONTooLarge) {
		t.Fatalf("decodeStrictJSON(oversized) = %v, want errLifecycleJSONTooLarge", err)
	}
}

func TestMCPDecoderHelpersEnforceRequestBound(t *testing.T) {
	oversized := []byte(strings.Repeat("x", maxMCPRequestBytes+1))
	if _, err := decodeMCPRequest(oversized); !errors.Is(err, ErrMCPRequestTooLarge) {
		t.Fatalf("oversized direct request decode error = %v, want ErrMCPRequestTooLarge", err)
	}

	var arguments struct{}
	err := decodeArguments(oversized, &arguments)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized direct argument decode error = %v, want ErrInvalid", err)
	}

	if err := decodeStrictMCPObject(oversized, &arguments); !errors.Is(err, ErrMCPRequestTooLarge) {
		t.Fatalf("oversized direct exact-object decode error = %v, want ErrMCPRequestTooLarge", err)
	}

	if err := rejectCaseVariantJSONMembers(oversized, &arguments); !errors.Is(err, ErrMCPRequestTooLarge) {
		t.Fatalf("oversized direct exact-member validation error = %v, want ErrMCPRequestTooLarge", err)
	}
}

func TestMCPParameterHelpersEnforceRequestBound(t *testing.T) {
	oversized := json.RawMessage(strings.Repeat("x", maxMCPRequestBytes+1))
	checks := map[string]func() error{
		"initialize parameters": func() error { return validateInitializeParams(oversized) },
		"empty parameters":      func() error { return validateEmptyParams(oversized) },
		"strict object":         func() error { return decodeStrictObject(oversized, &struct{}{}) },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, ErrMCPRequestTooLarge) {
				t.Fatalf("oversized direct helper error = %v, want ErrMCPRequestTooLarge", err)
			}
		})
	}
}

func TestMarshalMCPResponseNullsInvalidCorrelationIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   json.RawMessage
	}{
		{name: "boolean", id: json.RawMessage(`true`)},
		{name: "null", id: json.RawMessage(`null`)},
		{name: "trailing value", id: json.RawMessage(`1 2`)},
		{name: "trailing object", id: json.RawMessage(`"request" {}`)},
		{name: "invalid UTF-8", id: json.RawMessage([]byte{'"', 0xff, '"'})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := marshalMCPResponse(tc.id, map[string]any{"ok": true}, nil)
			if err != nil {
				t.Fatal(err)
			}
			response := decodeMCPResponse(t, raw)
			if response["id"] != nil {
				t.Fatalf("response ID = %#v, want null: %s", response["id"], raw)
			}
		})
	}
}

func TestMCPAdapterRejectsCanceledContextBeforeMutation(t *testing.T) {
	adapter, store := newMCPTestAdapter(t, "controller-a", ScopeProjectWrite)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	request := mcpToolRequest(t, 1, "lifecycle.project.create", map[string]any{
		"id":   "canceled-project",
		"name": "Must not be created",
	})
	if _, err := adapter.HandleContext(ctx, request); !errors.Is(err, ErrMCPRequestCanceled) {
		t.Fatalf("canceled context error = %v, want ErrMCPRequestCanceled", err)
	}
	if _, err := store.Project("canceled-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("canceled context mutated lifecycle state: %v", err)
	}

	var typedNil *typedNilMCPContext
	if _, err := adapter.HandleContext(typedNil, request); !errors.Is(err, ErrMCPRequestCanceled) {
		t.Fatalf("typed-nil context error = %v, want ErrMCPRequestCanceled", err)
	}

	if _, err := adapter.HandleContext(panickingMCPContext{}, request); !errors.Is(err, ErrMCPRequestCanceled) {
		t.Fatalf("panicking context error = %v, want ErrMCPRequestCanceled", err)
	}
	closedDone := make(chan struct{})
	close(closedDone)
	if _, err := adapter.HandleContext(closedDoneNilErrMCPContext{done: closedDone}, request); !errors.Is(err, ErrMCPRequestCanceled) {
		t.Fatalf("closed Done/nil Err context error = %v, want ErrMCPRequestCanceled", err)
	}
	if _, err := adapter.HandleContext(panickingDoneMCPContext{}, request); !errors.Is(err, ErrMCPRequestCanceled) {
		t.Fatalf("panicking Done context error = %v, want ErrMCPRequestCanceled", err)
	}
	if _, err := adapter.HandleContext(changingDoneMCPContext{}, request); !errors.Is(err, ErrMCPRequestCanceled) {
		t.Fatalf("changing Done context error = %v, want ErrMCPRequestCanceled", err)
	}
	if _, err := store.Project("canceled-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("panicking context mutated lifecycle state: %v", err)
	}
}

func TestMCPAdapterFailsClosedAfterStoreClose(t *testing.T) {
	adapter, store := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		request []byte
	}{
		{name: "initialize", request: buildMCPRequest(t, 1, "initialize", map[string]any{})},
		{name: "ping", request: buildMCPRequest(t, 2, "ping", nil)},
		{name: "tools list", request: buildMCPRequest(t, 3, "tools/list", nil)},
		{name: "tool call", request: mcpToolRequest(t, 4, "lifecycle.project.read", map[string]any{"id": "missing"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := adapter.Handle(tc.request); !errors.Is(err, ErrClosed) {
				t.Fatalf("closed adapter error = %v, want ErrClosed", err)
			}
		})
	}
}

func TestMCPAdapterRejectsMalformedInternalBinding(t *testing.T) {
	requests := []struct {
		name    string
		adapter *MCPAdapter
	}{
		{name: "nil adapter", adapter: nil},
		{name: "missing scoped controller", adapter: &MCPAdapter{}},
		{name: "missing owner controller", adapter: &MCPAdapter{controller: &ScopedController{}}},
		{name: "missing store", adapter: &MCPAdapter{controller: &ScopedController{controller: &Controller{}}}},
	}
	request := buildMCPRequest(t, 1, "ping", nil)
	for _, tc := range requests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.adapter.Handle(request); !errors.Is(err, ErrClosed) {
				t.Fatalf("malformed adapter error = %v, want ErrClosed", err)
			}
		})
	}

	validAdapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	{
		adapter := *validAdapter
		controller := *validAdapter.controller
		ownerController := *validAdapter.controller.controller
		ownerController.owner = ""
		controller.controller = &ownerController
		adapter.controller = &controller
		if _, err := adapter.Handle(request); !errors.Is(err, ErrClosed) {
			t.Fatalf("malformed owner binding error = %v, want ErrClosed", err)
		}
	}
	for _, tc := range []struct {
		name   string
		scopes map[string]struct{}
	}{
		{name: "nil scopes", scopes: nil},
		{name: "empty scopes", scopes: map[string]struct{}{}},
		{name: "unknown scope", scopes: map[string]struct{}{"lifecycle.unknown": {}}},
		{name: "widened scope map", scopes: map[string]struct{}{
			ScopeProjectRead: {}, ScopeProjectWrite: {}, ScopeTaskRead: {},
			ScopeTaskWrite: {}, ScopeTaskLease: {}, ScopeTaskRecover: {},
			"lifecycle.unknown": {},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := *validAdapter
			controller := *validAdapter.controller
			controller.scopes = tc.scopes
			adapter.controller = &controller
			if _, err := adapter.Handle(request); !errors.Is(err, ErrClosed) {
				t.Fatalf("malformed scope binding error = %v, want ErrClosed", err)
			}
		})
	}
}

func TestMCPAdapterRechecksContextAtToolDispatchBoundary(t *testing.T) {
	adapter, store := newMCPTestAdapter(t, "controller-a", ScopeProjectWrite)
	request := mcpToolRequest(t, 1, "lifecycle.project.create", map[string]any{
		"id":   "dispatch-canceled-project",
		"name": "Must not be created",
	})
	// The outer checks and the pre-decode check return nil. The post-decode
	// dispatch check then sees cancellation in the narrow interval before the
	// controller call.
	ctx := &cancelOnContextInspection{cancelAfter: 3}
	if _, err := adapter.HandleContext(ctx, request); !errors.Is(err, ErrMCPRequestCanceled) {
		t.Fatalf("dispatch-boundary cancellation error = %v, want ErrMCPRequestCanceled", err)
	}
	if _, err := store.Project("dispatch-canceled-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("dispatch-boundary cancellation mutated lifecycle state: %v", err)
	}
}

func TestMCPContextDoneRejectsNilToChannelChange(t *testing.T) {
	ctx := &nilThenChannelMCPContext{done: make(chan struct{})}
	if !mcpContextDone(ctx) {
		t.Fatal("context changing from nil Done to a channel was treated as live")
	}
}

func TestMCPContextDoneRechecksErrAfterDoneProbe(t *testing.T) {
	ctx := &errAfterDoneProbeMCPContext{}
	if !mcpContextDone(ctx) {
		t.Fatal("context canceled after the Done probe was treated as live")
	}
	if ctx.inspections != 2 {
		t.Fatalf("context Err inspections = %d, want initial and post-Done checks", ctx.inspections)
	}
}

type typedNilMCPContext struct{}

func (*typedNilMCPContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilMCPContext) Done() <-chan struct{}       { return nil }
func (*typedNilMCPContext) Err() error                  { return nil }
func (*typedNilMCPContext) Value(any) any               { return nil }

type panickingMCPContext struct{}

func (panickingMCPContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (panickingMCPContext) Done() <-chan struct{}       { return nil }
func (panickingMCPContext) Err() error                  { panic("context inspection panic") }
func (panickingMCPContext) Value(any) any               { return nil }

type closedDoneNilErrMCPContext struct {
	done <-chan struct{}
}

func (c closedDoneNilErrMCPContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c closedDoneNilErrMCPContext) Done() <-chan struct{}       { return c.done }
func (closedDoneNilErrMCPContext) Err() error                    { return nil }
func (closedDoneNilErrMCPContext) Value(any) any                 { return nil }

type panickingDoneMCPContext struct{}

func (panickingDoneMCPContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (panickingDoneMCPContext) Done() <-chan struct{}       { panic("context Done inspection panic") }
func (panickingDoneMCPContext) Err() error                  { return nil }
func (panickingDoneMCPContext) Value(any) any               { return nil }

type nilThenChannelMCPContext struct {
	done  <-chan struct{}
	calls int
}

func (*nilThenChannelMCPContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *nilThenChannelMCPContext) Done() <-chan struct{} {
	c.calls++
	if c.calls == 1 {
		return nil
	}
	return c.done
}
func (*nilThenChannelMCPContext) Err() error    { return nil }
func (*nilThenChannelMCPContext) Value(any) any { return nil }

type errAfterDoneProbeMCPContext struct {
	inspections int
}

func (*errAfterDoneProbeMCPContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*errAfterDoneProbeMCPContext) Done() <-chan struct{}       { return nil }
func (c *errAfterDoneProbeMCPContext) Err() error {
	c.inspections++
	if c.inspections >= 2 {
		return context.Canceled
	}
	return nil
}
func (*errAfterDoneProbeMCPContext) Value(any) any { return nil }

type cancelOnContextInspection struct {
	inspections int
	cancelAfter int
}

func (*cancelOnContextInspection) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*cancelOnContextInspection) Done() <-chan struct{}       { return nil }
func (c *cancelOnContextInspection) Err() error {
	c.inspections++
	if c.inspections > c.cancelAfter {
		return context.Canceled
	}
	return nil
}
func (*cancelOnContextInspection) Value(any) any { return nil }

func TestMCPAdapterListsOnlyToolsGrantedByScopes(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead, ScopeTaskLease)
	raw, err := adapter.Handle(buildMCPRequest(t, 1, "tools/list", nil))
	if err != nil {
		t.Fatal(err)
	}
	result := decodeMCPResponse(t, raw)["result"].(map[string]any)
	tools := result["tools"].([]any)
	got := make([]string, 0, len(tools))
	for _, rawTool := range tools {
		got = append(got, rawTool.(map[string]any)["name"].(string))
	}
	want := []string{
		"lifecycle.project.read",
		"lifecycle.task.acquire",
		"lifecycle.task.heartbeat",
		"lifecycle.task.checkpoint",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("authorized tools = %#v, want %#v", got, want)
	}
}

func TestMCPToolErrorUsesStableCodesAndRedactsUnexpectedErrors(t *testing.T) {
	wrappedConflict := fmt.Errorf("wrapped: %w", ErrConflict)
	for _, tc := range []struct {
		name string
		err  error
		code string
		text string
	}{
		{name: "invalid arguments", err: fmt.Errorf("%w: unknown field", ErrInvalid), code: "INVALID_ARGUMENT", text: "invalid lifecycle request: unknown field"},
		{name: "lease held", err: ErrLeaseHeld, code: "LEASE_HELD", text: ErrLeaseHeld.Error()},
		{name: "wrapped conflict", err: wrappedConflict, code: "CONFLICT", text: wrappedConflict.Error()},
		{name: "internal", err: errors.New("persist lifecycle state: /private/secret/path"), code: "INTERNAL", text: "lifecycle operation failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := toolResult(nil, tc.err)
			structured, ok := result.StructuredContent.(map[string]string)
			if !ok {
				t.Fatalf("structured error = %#v", result.StructuredContent)
			}
			if structured["code"] != tc.code || structured["message"] != tc.text {
				t.Fatalf("structured error = %#v, want code=%q message=%q", structured, tc.code, tc.text)
			}
			if result.Content[0].Text != tc.text {
				t.Fatalf("content text = %q, want %q", result.Content[0].Text, tc.text)
			}
		})
	}
}

type panickingMCPError struct {
	panicOnIs bool
}

func (panickingMCPError) Error() string {
	panic("malformed MCP error detail")
}

func (e panickingMCPError) Is(error) bool {
	if e.panicOnIs {
		panic("malformed MCP error matcher")
	}
	return true
}

func TestMCPToolErrorContainsMalformedErrorPanics(t *testing.T) {
	for _, err := range []error{
		panickingMCPError{},
		panickingMCPError{panicOnIs: true},
	} {
		result := toolResult(nil, err)
		if !result.IsError {
			t.Fatalf("malformed error result = %#v, want tool error", result)
		}
		structured, ok := result.StructuredContent.(map[string]string)
		if !ok {
			t.Fatalf("malformed error structured content = %#v", result.StructuredContent)
		}
		if structured["code"] != "INTERNAL" || structured["message"] != "lifecycle operation failed" {
			t.Fatalf("malformed error structured content = %#v, want generic INTERNAL", structured)
		}
		if result.Content[0].Text != "lifecycle operation failed" {
			t.Fatalf("malformed error content = %q, want generic message", result.Content[0].Text)
		}
	}
}

type cyclicMCPError struct {
	next error
}

func (*cyclicMCPError) Error() string { return "cyclic diagnostic" }

func (e *cyclicMCPError) Unwrap() error { return e.next }

func TestMCPToolErrorBoundsCyclicAndJoinedErrorChains(t *testing.T) {
	cycle := &cyclicMCPError{}
	cycle.next = cycle
	if code, message := mcpToolError(cycle); code != "INTERNAL" || message != "lifecycle operation failed" {
		t.Fatalf("cyclic error classification = (%q, %q), want generic INTERNAL", code, message)
	}

	joined := errors.Join(errors.New("unrelated"), fmt.Errorf("wrapped: %w", ErrInvalid))
	if code, message := mcpToolError(joined); code != "INVALID_ARGUMENT" || !strings.Contains(message, "invalid lifecycle request") {
		t.Fatalf("joined error classification = (%q, %q), want bounded INVALID_ARGUMENT detail", code, message)
	}
}

type panickingMCPJSONValue struct{}

func (panickingMCPJSONValue) MarshalJSON() ([]byte, error) {
	panic("malformed MCP JSON value")
}

func TestMCPToolResultContainsJSONMarshalPanics(t *testing.T) {
	result := toolResult(panickingMCPJSONValue{}, nil)
	if !result.IsError {
		t.Fatalf("panicking JSON value result = %#v, want tool error", result)
	}
	structured, ok := result.StructuredContent.(map[string]string)
	if !ok {
		t.Fatalf("panicking JSON value structured content = %#v", result.StructuredContent)
	}
	if structured["code"] != "INTERNAL" || structured["message"] != "lifecycle operation failed" {
		t.Fatalf("panicking JSON value structured content = %#v, want generic INTERNAL", structured)
	}
	if result.Content[0].Text != "lifecycle operation failed" {
		t.Fatalf("panicking JSON value content = %q, want generic message", result.Content[0].Text)
	}
}

func TestMCPToolErrorBoundsExpectedDetailWithoutBreakingResponse(t *testing.T) {
	message := "invalid field: " + strings.Repeat("界", maxMCPErrorMessageBytes)
	result := toolResult(nil, fmt.Errorf("%w: %s", ErrInvalid, message))
	if !result.IsError {
		t.Fatal("oversized expected error was not returned as a tool error")
	}
	structured, ok := result.StructuredContent.(map[string]string)
	if !ok {
		t.Fatalf("structured error = %#v", result.StructuredContent)
	}
	if structured["code"] != "INVALID_ARGUMENT" {
		t.Fatalf("error code = %q, want INVALID_ARGUMENT", structured["code"])
	}
	if len(structured["message"]) > maxMCPErrorMessageBytes || !strings.HasSuffix(structured["message"], "...") {
		t.Fatalf("error message length/suffix = %d/%q, want <= %d and ellipsis", len(structured["message"]), structured["message"][max(0, len(structured["message"])-3):], maxMCPErrorMessageBytes)
	}
	if !utf8.ValidString(structured["message"]) {
		t.Fatal("bounded error message is not valid UTF-8")
	}
	if _, err := marshalMCPResponse(json.RawMessage(`1`), result, nil); err != nil {
		t.Fatalf("bounded expected error response = %v", err)
	}
}

func TestMCPToolErrorNormalizesInvalidUTF8BeforeBounding(t *testing.T) {
	message := string(append([]byte("invalid field: "), 0xff, 0xfe))
	result := toolResult(nil, fmt.Errorf("%w: %s", ErrInvalid, message))
	if !result.IsError {
		t.Fatal("invalid UTF-8 expected error was not returned as a tool error")
	}
	structured, ok := result.StructuredContent.(map[string]string)
	if !ok {
		t.Fatalf("structured error = %#v", result.StructuredContent)
	}
	if !utf8.ValidString(structured["message"]) {
		t.Fatalf("structured message is not valid UTF-8: %q", structured["message"])
	}
	if !strings.Contains(structured["message"], "\uFFFD") {
		t.Fatalf("structured message = %q, want replacement character", structured["message"])
	}
	if len(structured["message"]) > maxMCPErrorMessageBytes {
		t.Fatalf("structured message length = %d, want <= %d", len(structured["message"]), maxMCPErrorMessageBytes)
	}
	raw, err := marshalMCPResponse(json.RawMessage(`1`), result, nil)
	if err != nil {
		t.Fatalf("normalized expected error response = %v", err)
	}
	if !utf8.Valid(raw) {
		t.Fatal("MCP response is not valid UTF-8")
	}
}

func TestMCPToolErrorBoundsLargeInvalidUTF8Detail(t *testing.T) {
	message := "invalid field: " + strings.Repeat(string([]byte{0xff}), maxMCPErrorMessageBytes*64)
	result := toolResult(nil, fmt.Errorf("%w: %s", ErrInvalid, message))
	structured, ok := result.StructuredContent.(map[string]string)
	if !ok {
		t.Fatalf("structured error = %#v", result.StructuredContent)
	}
	bounded := structured["message"]
	if len(bounded) > maxMCPErrorMessageBytes {
		t.Fatalf("bounded error message length = %d, want <= %d", len(bounded), maxMCPErrorMessageBytes)
	}
	if !strings.HasSuffix(bounded, "...") {
		t.Fatalf("bounded error message = %q, want ellipsis", bounded)
	}
	if !strings.Contains(bounded, "\uFFFD") {
		t.Fatalf("bounded error message = %q, want replacement character", bounded)
	}
	if !utf8.ValidString(bounded) {
		t.Fatal("bounded error message is not valid UTF-8")
	}
}

func TestMCPToolResultRedactsResultSerializationFailure(t *testing.T) {
	raw, err := marshalMCPResponse(json.RawMessage(`1`), toolResult(func() {}, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeMCPResponse(t, raw)
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("result = %#v, want tool result", response["result"])
	}
	if result["isError"] != true {
		t.Fatalf("isError = %#v, want true", result["isError"])
	}
	if got := result["content"].([]any)[0].(map[string]any)["text"]; got != "lifecycle operation failed" {
		t.Fatalf("content text = %#v, want redacted internal message", got)
	}
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok || structured["code"] != "INTERNAL" || structured["message"] != "lifecycle operation failed" {
		t.Fatalf("structured content = %#v, want bounded INTERNAL error", result["structuredContent"])
	}
	if strings.Contains(string(raw), "unsupported type") || strings.Contains(string(raw), "func()") {
		t.Fatalf("serialization diagnostic escaped response: %s", raw)
	}
}

func TestMCPToolResultBoundsSuccessfulSerialization(t *testing.T) {
	result := toolResult(strings.Repeat("x", maxMCPResponseBytes), nil)
	if !result.IsError {
		t.Fatal("oversized successful result was not converted to a tool error")
	}
	if got := result.Content[0].Text; got != "lifecycle operation failed" {
		t.Fatalf("content text = %q, want redacted internal message", got)
	}
	structured, ok := result.StructuredContent.(map[string]string)
	if !ok || structured["code"] != "INTERNAL" || structured["message"] != "lifecycle operation failed" {
		t.Fatalf("structured content = %#v, want bounded INTERNAL error", result.StructuredContent)
	}
}

func TestMCPToolResponseRedactsAggregateOversize(t *testing.T) {
	// The controller value fits the per-value bound, but MCP repeats it in
	// content.text and structuredContent. The complete response must remain
	// within the aggregate response budget and retain a JSON-RPC result.
	value := strings.Repeat("x", maxMCPResponseBytes/2)
	raw, err := marshalMCPToolResponse(json.RawMessage(`1`), value, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxMCPResponseBytes {
		t.Fatalf("response length = %d, want <= %d", len(raw), maxMCPResponseBytes)
	}
	response := decodeMCPResponse(t, raw)
	result, ok := response["result"].(map[string]any)
	if !ok || result["isError"] != true {
		t.Fatalf("aggregate-oversized result = %#v, want bounded tool error", response)
	}
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok || structured["code"] != "INTERNAL" {
		t.Fatalf("aggregate-oversized structured content = %#v, want INTERNAL", result["structuredContent"])
	}
}

func TestMCPAdapterPublishesTaskCreateSchemaThatMatchesImplementation(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeTaskWrite)
	raw, err := adapter.Handle(buildMCPRequest(t, 1, "tools/list", nil))
	if err != nil {
		t.Fatal(err)
	}
	response := decodeMCPResponse(t, raw)
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/list result = %#v", response["result"])
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("tools/list tools = %#v", result["tools"])
	}
	for _, rawTool := range tools {
		tool, ok := rawTool.(map[string]any)
		if !ok || tool["name"] != "lifecycle.task.create" {
			continue
		}
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok {
			t.Fatalf("task.create input schema = %#v", tool["inputSchema"])
		}
		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("task.create properties = %#v", schema["properties"])
		}
		if _, ok := properties["id"]; !ok {
			t.Fatal("task.create schema omits required id property")
		}
		if got := properties["id"].(map[string]any)["maxLength"]; got != float64(maxIDLength) {
			t.Fatalf("task ID maxLength = %#v, want %d", got, maxIDLength)
		}
		if got := properties["project_id"].(map[string]any)["maxLength"]; got != float64(maxIDLength) {
			t.Fatalf("project ID maxLength = %#v, want %d", got, maxIDLength)
		}
		required, ok := schema["required"].([]any)
		if !ok {
			t.Fatalf("task.create required = %#v", schema["required"])
		}
		if len(required) != 2 || required[0] != "id" || required[1] != "project_id" {
			t.Fatalf("task.create required = %#v, want [id project_id]", required)
		}
		if schema["additionalProperties"] != false {
			t.Fatalf("task.create additionalProperties = %#v, want false", schema["additionalProperties"])
		}
		dependencies := properties["dependencies"].(map[string]any)
		if dependencies["maxItems"] != float64(maxTaskDependencies) {
			t.Fatalf("task dependency maxItems = %#v, want %d", dependencies["maxItems"], maxTaskDependencies)
		}
		if got := properties["idempotency_key"].(map[string]any)["maxLength"]; got != float64(maxIDLength) {
			t.Fatalf("idempotency key maxLength = %#v, want %d", got, maxIDLength)
		}
		return
	}
	t.Fatal("tools/list omitted lifecycle.task.create")
}

func TestMCPAdapterPublishesProjectNameByteCeiling(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectWrite)
	raw, err := adapter.Handle(buildMCPRequest(t, 1, "tools/list", nil))
	if err != nil {
		t.Fatal(err)
	}
	tools := decodeMCPResponse(t, raw)["result"].(map[string]any)["tools"].([]any)
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		if tool["name"] != "lifecycle.project.create" {
			continue
		}
		properties := tool["inputSchema"].(map[string]any)["properties"].(map[string]any)
		name := properties["name"].(map[string]any)
		if name["minLength"] != float64(1) || name["maxLength"] != float64(maxNameLength) {
			t.Fatalf("project name schema = %#v, want minLength 1 and maxLength %d", name, maxNameLength)
		}
		return
	}
	t.Fatal("tools/list omitted lifecycle.project.create")
}

func TestMCPAdapterPublishesNonEmptyIdentityConstraints(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	raw, err := adapter.Handle(buildMCPRequest(t, 1, "tools/list", nil))
	if err != nil {
		t.Fatal(err)
	}
	tools := decodeMCPResponse(t, raw)["result"].(map[string]any)["tools"].([]any)
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		schema := tool["inputSchema"].(map[string]any)
		properties := schema["properties"].(map[string]any)
		required, _ := schema["required"].([]any)
		for _, field := range required {
			name := field.(string)
			property, ok := properties[name].(map[string]any)
			if !ok || property["type"] != "string" {
				continue
			}
			if property["minLength"] != float64(1) {
				t.Fatalf("%s required string %q schema = %#v, want minLength 1", tool["name"], name, property)
			}
		}
		if tool["name"] == "lifecycle.task.create" {
			dependencies := properties["dependencies"].(map[string]any)
			item := dependencies["items"].(map[string]any)
			if item["minLength"] != float64(1) {
				t.Fatalf("task dependency item schema = %#v, want minLength 1", item)
			}
		}
	}
}

func TestMCPAdapterPublishesObjectSchemaRequiredArrays(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead, ScopeTaskRecover)
	raw, err := adapter.Handle(buildMCPRequest(t, 1, "tools/list", nil))
	if err != nil {
		t.Fatal(err)
	}
	tools := decodeMCPResponse(t, raw)["result"].(map[string]any)["tools"].([]any)
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		schema := tool["inputSchema"].(map[string]any)
		required, ok := schema["required"].([]any)
		if !ok {
			t.Fatalf("%s required schema = %#v, want JSON array", tool["name"], schema["required"])
		}
		if tool["name"] == "lifecycle.task.recover_expired" && len(required) != 0 {
			t.Fatalf("recover_expired required schema = %#v, want empty array", required)
		}
	}
}

func TestMCPAdapterPublishesTruthfulToolSafetyAnnotations(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead, ScopeProjectWrite, ScopeTaskRead, ScopeTaskWrite, ScopeTaskLease, ScopeTaskRecover)
	raw, err := adapter.Handle(buildMCPRequest(t, 1, "tools/list", nil))
	if err != nil {
		t.Fatal(err)
	}
	tools := decodeMCPResponse(t, raw)["result"].(map[string]any)["tools"].([]any)
	want := map[string]map[string]bool{
		"lifecycle.project.create":       {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false},
		"lifecycle.project.archive":      {"readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": false},
		"lifecycle.project.read":         {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		"lifecycle.task.create":          {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false},
		"lifecycle.task.read":            {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		"lifecycle.task.list":            {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		"lifecycle.task.ready":           {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		"lifecycle.task.acquire":         {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false},
		"lifecycle.task.heartbeat":       {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false},
		"lifecycle.task.checkpoint":      {"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false},
		"lifecycle.task.recover_expired": {"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false},
	}
	if len(tools) != len(want) {
		t.Fatalf("tool count = %d, want %d", len(tools), len(want))
	}
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		name := tool["name"].(string)
		annotations, ok := tool["annotations"].(map[string]any)
		if !ok {
			t.Fatalf("%s annotations = %#v, want object", name, tool["annotations"])
		}
		wantAnnotations, ok := want[name]
		if !ok {
			t.Fatalf("unexpected tool %q", name)
		}
		if annotations["title"] != tool["description"] {
			t.Fatalf("%s title = %#v, want description %q", name, annotations["title"], tool["description"])
		}
		for key, value := range wantAnnotations {
			if got, ok := annotations[key].(bool); !ok || got != value {
				t.Fatalf("%s %s = %#v, want %t", name, key, annotations[key], value)
			}
		}
	}
}

func TestMCPAdapterPublishesLeaseBoundsAndCheckpointStates(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeTaskLease)
	raw, err := adapter.Handle(buildMCPRequest(t, 1, "tools/list", nil))
	if err != nil {
		t.Fatal(err)
	}
	response := decodeMCPResponse(t, raw)
	tools := response["result"].(map[string]any)["tools"].([]any)
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		name := tool["name"].(string)
		if name != "lifecycle.task.acquire" && name != "lifecycle.task.heartbeat" && name != "lifecycle.task.checkpoint" {
			continue
		}
		schema := tool["inputSchema"].(map[string]any)["properties"].(map[string]any)
		if name == "lifecycle.task.acquire" || name == "lifecycle.task.heartbeat" {
			ttl := schema["ttl_seconds"].(map[string]any)
			if ttl["minimum"] != float64(1) || ttl["maximum"] != float64(maxLease/time.Second) {
				t.Fatalf("%s TTL schema = %#v", name, ttl)
			}
		}
		if name == "lifecycle.task.heartbeat" || name == "lifecycle.task.checkpoint" {
			version := schema["version"].(map[string]any)
			if version["minimum"] != float64(1) {
				t.Fatalf("%s version schema = %#v", name, version)
			}
		}
		if name == "lifecycle.task.checkpoint" {
			state := schema["state"].(map[string]any)
			if len(state["enum"].([]any)) != 4 {
				t.Fatalf("checkpoint state schema = %#v", state)
			}
			payload := schema["payload"].(map[string]any)
			if payload["type"] != "string" || payload["maxLength"] != float64(maxPayloadBytes) {
				t.Fatalf("checkpoint payload schema = %#v, want bounded string", payload)
			}
		}
	}
}

func TestMCPAdapterRejectsExcessiveJSONNesting(t *testing.T) {
	adapter, _ := newMCPTestAdapter(t, "controller-a", ScopeProjectRead)
	request := `{"jsonrpc":"2.0","id":1,"method":"ping","params":` +
		strings.Repeat("[", maxMCPJSONDepth+1) + "0" +
		strings.Repeat("]", maxMCPJSONDepth+1) + "}"
	raw, err := adapter.Handle([]byte(request))
	if err != nil {
		t.Fatal(err)
	}
	response := decodeMCPResponse(t, raw)
	if response["error"] == nil {
		t.Fatalf("deeply nested request unexpectedly succeeded: %s", raw)
	}

	deepArray := strings.Repeat("[", maxMCPJSONDepth+1) + "0" + strings.Repeat("]", maxMCPJSONDepth+1)
	if _, err := decodeMCPRequest([]byte(deepArray)); err == nil ||
		!strings.Contains(err.Error(), "JSON nesting exceeds limit") {
		t.Fatalf("deeply nested top-level array error = %v, want JSON nesting bound", err)
	}
}

func TestMCPAdapterRejectsOverflowingOrOutOfRangeLeaseTTL(t *testing.T) {
	adapter, store := newMCPTestAdapter(t, "controller-a", ScopeProjectWrite, ScopeTaskWrite, ScopeTaskLease, ScopeTaskRead)
	if _, err := adapter.Handle(mcpToolRequest(t, 1, "lifecycle.project.create", map[string]any{"id": "p", "name": "Project"})); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Handle(mcpToolRequest(t, 2, "lifecycle.task.create", map[string]any{"id": "task", "project_id": "p"})); err != nil {
		t.Fatal(err)
	}

	for id, seconds := range map[int]int64{
		3: 0,
		4: -1,
		5: 3601,
		6: int64(^uint64(0) >> 1),
	} {
		raw, err := adapter.Handle(mcpToolRequest(t, id, "lifecycle.task.acquire", map[string]any{
			"task_id": "task", "ttl_seconds": seconds,
		}))
		if err != nil {
			t.Fatal(err)
		}
		tool := decodeMCPResponse(t, raw)["result"].(map[string]any)
		if tool["isError"] != true {
			t.Fatalf("TTL %d unexpectedly acquired lease: %#v", seconds, tool)
		}
	}
	task, err := store.Task("task")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != TaskPending || task.Attempt != 0 {
		t.Fatalf("invalid TTL requests changed task state: %#v", task)
	}
}

func TestMCPAdapterRejectsAcquireVersionField(t *testing.T) {
	adapter, store := newMCPTestAdapter(t, "controller-a", ScopeProjectWrite, ScopeTaskWrite, ScopeTaskLease)
	if _, err := adapter.Handle(mcpToolRequest(t, 1, "lifecycle.project.create", map[string]any{"id": "p", "name": "Project"})); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Handle(mcpToolRequest(t, 2, "lifecycle.task.create", map[string]any{"id": "task", "project_id": "p"})); err != nil {
		t.Fatal(err)
	}

	raw, err := adapter.Handle(mcpToolRequest(t, 3, "lifecycle.task.acquire", map[string]any{
		"task_id":     "task",
		"ttl_seconds": 30,
		"version":     1,
	}))
	if err != nil {
		t.Fatal(err)
	}
	tool := decodeMCPResponse(t, raw)["result"].(map[string]any)
	if tool["isError"] != true {
		t.Fatalf("acquire accepted schema-undocumented version field: %#v", tool)
	}
	task, err := store.Task("task")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != TaskPending || task.Attempt != 0 {
		t.Fatalf("schema rejection mutated task: %#v", task)
	}
}

func TestMCPAdapterRejectsExplicitNullForSchemaTypedArguments(t *testing.T) {
	adapter, store := newMCPTestAdapter(t, "controller-a", ScopeProjectWrite, ScopeTaskWrite, ScopeTaskLease)
	if _, err := adapter.Handle(mcpToolRequest(t, 1, "lifecycle.project.create", map[string]any{"id": "p", "name": "Project"})); err != nil {
		t.Fatal(err)
	}

	for id, arguments := range map[int]map[string]any{
		2: {"id": "null-dependencies", "project_id": "p", "dependencies": nil},
		3: {"id": "null-idempotency", "project_id": "p", "idempotency_key": nil},
	} {
		raw, err := adapter.Handle(mcpToolRequest(t, id, "lifecycle.task.create", arguments))
		if err != nil {
			t.Fatal(err)
		}
		tool := decodeMCPResponse(t, raw)["result"].(map[string]any)
		if tool["isError"] != true {
			t.Fatalf("task.create accepted explicit null argument %#v: %v", arguments, tool)
		}
	}

	if _, err := adapter.Handle(mcpToolRequest(t, 4, "lifecycle.task.create", map[string]any{"id": "task", "project_id": "p"})); err != nil {
		t.Fatal(err)
	}
	raw, err := adapter.Handle(mcpToolRequest(t, 5, "lifecycle.task.acquire", map[string]any{"task_id": "task", "ttl_seconds": 30}))
	if err != nil {
		t.Fatal(err)
	}
	lease := decodeMCPResponse(t, raw)["result"].(map[string]any)["structuredContent"].(map[string]any)

	raw, err = adapter.Handle(mcpToolRequest(t, 6, "lifecycle.task.checkpoint", map[string]any{
		"task_id": "task", "version": lease["version"], "state": "running", "payload": nil,
	}))
	if err != nil {
		t.Fatal(err)
	}
	tool := decodeMCPResponse(t, raw)["result"].(map[string]any)
	if tool["isError"] != true {
		t.Fatalf("checkpoint accepted explicit null payload: %v", tool)
	}
	task, err := store.Task("task")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != TaskRunning || task.Checkpoint != nil {
		t.Fatalf("null checkpoint payload changed lifecycle state: %#v", task)
	}
}
