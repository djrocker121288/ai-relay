package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MCPProtocolVersion is the protocol version advertised by this additive
	// v2 adapter. It does not change the legacy gateway's MCP surface.
	MCPProtocolVersion      = "2025-06-18"
	maxMCPRequestBytes      = 64 << 10
	maxMCPResponseBytes     = 256 << 10
	maxMCPErrorMessageBytes = 8 << 10
	maxMCPJSONDepth         = 128
	maxMCPContentTypeBytes  = 256
	// Error values can come from an in-process integration. Bound traversal of
	// their unwrap graph so a cyclic or excessively deep diagnostic cannot hang
	// the authenticated MCP boundary while it is being classified.
	maxMCPErrorChainNodes = 64
)

var (
	ErrMCPRequestTooLarge    = errors.New("lifecycle MCP request exceeds limit")
	ErrMCPResponseTooLarge   = errors.New("lifecycle MCP response exceeds limit")
	ErrMCPRequestCanceled    = errors.New("lifecycle MCP request context ended")
	errLifecycleJSONTooLarge = errors.New("lifecycle JSON input exceeds limit")
	errMCPInvalidRequest     = errors.New("invalid lifecycle MCP request envelope")
	errMCPJSONMarshalPanic   = errors.New("lifecycle MCP JSON encoding failed")
)

// boundedJSONWriter gives encoding/json a fixed aggregate output ceiling. A
// final len check alone would still let an oversized value allocate an
// unbounded intermediate buffer before the MCP response is rejected.
type boundedJSONWriter struct {
	bytes.Buffer
	limit int
}

func (w *boundedJSONWriter) Write(p []byte) (int, error) {
	// marshalBoundedJSON always supplies a concrete writer, but keep this
	// lowest writer seam fail-closed for direct or future in-process callers.
	// A malformed nil receiver must not turn response construction into a
	// panic-shaped transport failure.
	if w == nil {
		return 0, ErrMCPResponseTooLarge
	}
	if len(p) > w.limit-w.Len() {
		return 0, ErrMCPResponseTooLarge
	}
	return w.Buffer.Write(p)
}

func marshalBoundedJSON(value any, limit int) (encoded []byte, err error) {
	// encoding/json invokes caller-controlled Marshaler and TextMarshaler
	// methods. A malformed in-process value must not turn the authenticated MCP
	// boundary into a process panic or expose the panic value to the caller.
	defer func() {
		if recover() != nil {
			encoded = nil
			err = errMCPJSONMarshalPanic
		}
	}()
	// The encoder writes one trailing newline, so the writer ceiling is
	// limit+1. Reject invalid and overlarge internal bounds before that addition
	// can wrap or weaken the protocol's fixed response ceiling.
	if limit < 1 || limit > maxMCPResponseBytes || limit == int(^uint(0)>>1) {
		return nil, ErrMCPResponseTooLarge
	}
	var output boundedJSONWriter
	// Encoder adds one trailing newline. Allow it inside the writer and remove
	// it before returning so the bound applies to the JSON value itself.
	output.limit = limit + 1
	if err := json.NewEncoder(&output).Encode(value); err != nil {
		return nil, err
	}
	raw := output.Bytes()
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
	}
	if len(raw) > limit {
		return nil, ErrMCPResponseTooLarge
	}
	return append([]byte(nil), raw...), nil
}

// MCPAdapter is the transport-facing, authenticated-principal boundary for
// lifecycle. Authentication and HTTPS remain outside this type: the caller
// must construct it with an already authenticated Principal. The adapter
// never accepts an owner in tool arguments.
type MCPAdapter struct {
	controller *ScopedController
}

// NewMCPAdapter binds one authenticated principal and its explicit lifecycle
// scopes to one store. It is additive and does not modify the 1.x gateway.
func NewMCPAdapter(store *Store, principal Principal) (*MCPAdapter, error) {
	controller, err := NewScopedController(store, principal)
	if err != nil {
		return nil, err
	}
	return &MCPAdapter{controller: controller}, nil
}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolResult struct {
	Content           []mcpContent `json:"content"`
	IsError           bool         `json:"isError"`
	StructuredContent any          `json:"structuredContent"`
}

// Handle processes one bounded JSON-RPC request with a context that cannot be
// canceled. Transport callers that own a request context should use
// HandleContext so an already-ended request cannot reach a lifecycle mutation.
func (a *MCPAdapter) Handle(request []byte) ([]byte, error) {
	return a.HandleContext(context.Background(), request)
}

// HandleContext processes one bounded JSON-RPC request after checking the
// caller's context at the mutating dispatch boundary. Protocol and schema
// failures are returned as JSON-RPC errors. A notification is accepted only
// for the side-effect-free initialized event; side-effecting notifications are
// ignored without executing a lifecycle operation. Cancellation is returned as
// ErrMCPRequestCanceled so an HTTP transport can map it to a generic timeout
// without exposing context details in the MCP response.
func (a *MCPAdapter) HandleContext(ctx context.Context, request []byte) ([]byte, error) {
	if mcpContextDone(ctx) {
		return nil, ErrMCPRequestCanceled
	}
	// Protocol methods do not call a lifecycle store operation, but the
	// adapter remains bound to that store's writer lock and durable state. Do
	// not let a stale adapter continue a handshake or advertise tools after
	// the store has been closed; the HTTP boundary maps this fail-closed result
	// to service-unavailable and direct callers can reopen/rebind explicitly.
	if err := a.ensureReady(); err != nil {
		return nil, err
	}
	if len(request) > maxMCPRequestBytes {
		return nil, ErrMCPRequestTooLarge
	}
	q, err := decodeMCPRequest(request)
	if err != nil {
		if errors.Is(err, errMCPInvalidRequest) {
			return marshalMCPResponse(nil, nil, &mcpError{Code: -32600, Message: "Invalid Request"})
		}
		return marshalMCPResponse(nil, nil, &mcpError{Code: -32700, Message: "Parse error"})
	}
	validID := validMCPID(q.ID)
	if q.JSONRPC != "2.0" || q.Method == "" || !validID {
		// JSON-RPC cannot correlate an error to an ID whose type is invalid.
		// Do not reflect an attacker-controlled object, boolean, or null as the
		// response ID; malformed requests use the protocol-mandated null ID.
		if !validID {
			return marshalMCPResponse(nil, nil, &mcpError{Code: -32600, Message: "Invalid Request"})
		}
		return marshalMCPResponse(q.ID, nil, &mcpError{Code: -32600, Message: "Invalid Request"})
	}
	if len(q.ID) == 0 {
		if q.Method == "notifications/initialized" {
			return nil, nil
		}
		// Do not execute a mutating operation without a response correlation ID.
		return nil, nil
	}

	switch q.Method {
	case "initialize":
		if err := validateInitializeParams(q.Params); err != nil {
			return marshalMCPResponse(q.ID, nil, &mcpError{Code: -32602, Message: "unsupported initialize parameters"})
		}
		return marshalMCPResponse(q.ID, map[string]any{
			"protocolVersion": MCPProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "ai-relay-lifecycle", "version": APIVersion},
		}, nil)
	case "ping":
		if err := validateEmptyParams(q.Params); err != nil {
			return marshalMCPResponse(q.ID, nil, &mcpError{Code: -32602, Message: "unsupported ping parameters"})
		}
		return marshalMCPResponse(q.ID, map[string]any{}, nil)
	case "tools/list":
		if err := validateEmptyParams(q.Params); err != nil {
			return marshalMCPResponse(q.ID, nil, &mcpError{Code: -32602, Message: "unsupported tools/list parameters"})
		}
		return marshalMCPResponse(q.ID, map[string]any{"tools": a.listTools()}, nil)
	case "tools/call":
		var call mcpToolCall
		if err := decodeStrictObject(q.Params, &call); err != nil || call.Name == "" {
			return marshalMCPResponse(q.ID, nil, &mcpError{Code: -32602, Message: "tools/call requires a tool name and object arguments"})
		}
		if !knownLifecycleTool(call.Name) {
			return marshalMCPResponse(q.ID, nil, &mcpError{Code: -32602, Message: "unknown lifecycle tool"})
		}
		if mcpContextDone(ctx) {
			return nil, ErrMCPRequestCanceled
		}
		value, err := a.call(ctx, call.Name, call.Arguments)
		if errors.Is(err, ErrMCPRequestCanceled) {
			return nil, err
		}
		return marshalMCPToolResponse(q.ID, value, err)
	default:
		return marshalMCPResponse(q.ID, nil, &mcpError{Code: -32601, Message: "Method not found"})
	}
}

// ensureReady validates the complete in-process adapter binding before any
// request parsing or capability advertisement. Constructors create all of
// these links, but an integration seam can still hand the package a malformed
// value; that must fail closed rather than panic while dereferencing a nested
// controller or store pointer.
func (a *MCPAdapter) ensureReady() error {
	if a == nil || a.controller == nil {
		return ErrClosed
	}
	// The owner and scope allowlist are authenticated binding state, not request
	// data. Reuse the direct controller's fail-closed invariant so in-process
	// callers cannot retain discovery/read authority through a malformed value.
	if !a.controller.bindingValid() {
		return ErrClosed
	}
	return a.controller.controller.store.ensureAdapterReady()
}

// decodeMCPRequest keeps JSON syntax failures separate from a well-formed JSON
// value that cannot be a JSON-RPC request object. encoding/json reports both
// cases as decode errors when decoding directly into a typed struct, which
// would incorrectly turn valid-but-invalid requests into parse errors.
func decodeMCPRequest(raw []byte) (mcpRequest, error) {
	// HandleContext checks the complete request before calling this helper, but
	// keep the parser boundary safe for direct and future internal callers too.
	// Without this guard, a helper call could bypass the adapter's documented
	// 64 KiB resource ceiling before JSON decoding begins.
	if len(raw) > maxMCPRequestBytes {
		return mcpRequest{}, ErrMCPRequestTooLarge
	}
	var value json.RawMessage
	if err := decodeSingleJSONValue(raw, &value); err != nil {
		return mcpRequest{}, err
	}
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		// Apply the same recursive duplicate-key and nesting policy to
		// well-formed non-object JSON values before classifying them as an
		// invalid JSON-RPC envelope. Otherwise a deeply nested top-level array
		// would bypass the adapter's documented JSON-depth bound.
		if err := rejectDuplicateJSONKeys(raw); err != nil {
			return mcpRequest{}, fmt.Errorf("%w: %v", errMCPInvalidRequest, err)
		}
		return mcpRequest{}, errMCPInvalidRequest
	}

	var fields struct {
		JSONRPC json.RawMessage `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  json.RawMessage `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := decodeStrictMCPObject(raw, &fields); err != nil {
		// The syntax was already accepted above. Duplicate or unknown envelope
		// fields, excessive nesting, and typed-field mismatches are therefore
		// well-formed JSON-RPC values that fail the request contract, not parse
		// errors.
		return mcpRequest{}, fmt.Errorf("%w: %v", errMCPInvalidRequest, err)
	}
	request := mcpRequest{ID: fields.ID, Params: fields.Params}
	if len(fields.JSONRPC) > 0 {
		if err := json.Unmarshal(fields.JSONRPC, &request.JSONRPC); err != nil {
			return mcpRequest{}, errMCPInvalidRequest
		}
	}
	if len(fields.Method) > 0 {
		if err := json.Unmarshal(fields.Method, &request.Method); err != nil {
			return mcpRequest{}, errMCPInvalidRequest
		}
	}
	return request, nil
}

// decodeSingleJSONValue separates JSON syntax/framing errors from the stricter
// request-contract checks performed by decodeStrictJSON. A JSON value followed
// by another value is not one JSON-RPC message and remains a parse error.
func decodeSingleJSONValue(raw []byte, dst any) error {
	// The enclosing request decoder checks this before calling the helper, but
	// keep the lowest-level JSON framing boundary safe for direct and future
	// internal callers too.
	if len(raw) > maxMCPRequestBytes {
		return ErrMCPRequestTooLarge
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

// mcpContextDone treats literal- and typed-nil contexts as an ended request.
// Context is an interface, so checking only ctx == nil would otherwise allow
// malformed direct callers to panic while the adapter is deciding whether to
// mutate lifecycle state. A malformed non-nil context whose Err or Done method
// panics is also treated as ended. A closed Done channel is authoritative even
// when a malformed context incorrectly reports a nil Err.
func mcpContextDone(ctx context.Context) (done bool) {
	done = true
	defer func() {
		if recover() != nil {
			done = true
		}
	}()
	if ctx == nil {
		return true
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return true
		}
	}
	if ctx.Err() != nil {
		return true
	}
	ended := ctx.Done()
	// context.Context requires Done to return the same channel on every call.
	// Verify that contract even when the first result is nil; otherwise a
	// malformed implementation could swap a non-cancelable result for a
	// cancellation channel between the two observations and hide cancellation
	// from a mutation boundary.
	if repeated := ctx.Done(); repeated != ended {
		return true
	}
	// Recheck Err after the Done contract has been observed. A normal context
	// may become canceled in this small interval, and a malformed context could
	// otherwise transition from a nil Err to cancellation while exposing a nil
	// Done channel. Either case must fail closed before lifecycle dispatch.
	if ctx.Err() != nil {
		return true
	}
	if ended == nil {
		return false
	}
	select {
	case <-ended:
		return true
	default:
		return false
	}
}

func (a *MCPAdapter) listTools() []map[string]any {
	if a == nil || a.controller == nil {
		return []map[string]any{}
	}
	all := lifecycleTools()
	tools := make([]map[string]any, 0, len(all))
	for _, tool := range all {
		name, ok := tool["name"].(string)
		if !ok {
			continue
		}
		scope, ok := lifecycleToolScope(name)
		if ok && a.controller.allows(scope) {
			tools = append(tools, tool)
		}
	}
	return tools
}

func lifecycleToolScope(name string) (string, bool) {
	switch name {
	case "lifecycle.project.create", "lifecycle.project.archive":
		return ScopeProjectWrite, true
	case "lifecycle.project.read":
		return ScopeProjectRead, true
	case "lifecycle.task.create":
		return ScopeTaskWrite, true
	case "lifecycle.task.read", "lifecycle.task.list", "lifecycle.task.ready":
		return ScopeTaskRead, true
	case "lifecycle.task.acquire", "lifecycle.task.heartbeat", "lifecycle.task.checkpoint":
		return ScopeTaskLease, true
	case "lifecycle.task.recover_expired":
		return ScopeTaskRecover, true
	default:
		return "", false
	}
}

func (a *MCPAdapter) call(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	// The caller may cancel after the outer tools/call check but before this
	// helper runs. Recheck immediately before argument decode, then again after
	// decoding immediately before controller dispatch so a stale request cannot
	// reach a mutating store operation.
	if mcpContextDone(ctx) {
		return nil, ErrMCPRequestCanceled
	}
	dispatch := func(fn func() (any, error)) (any, error) {
		if mcpContextDone(ctx) {
			return nil, ErrMCPRequestCanceled
		}
		return fn()
	}
	switch name {
	case "lifecycle.project.create":
		var args struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		return dispatch(func() (any, error) { return a.controller.CreateProject(args.ID, args.Name) })
	case "lifecycle.project.archive":
		var args struct {
			ID string `json:"id"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		return dispatch(func() (any, error) { return a.controller.ArchiveProject(args.ID) })
	case "lifecycle.project.read":
		var args struct {
			ID string `json:"id"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		return dispatch(func() (any, error) { return a.controller.Project(args.ID) })
	case "lifecycle.task.create":
		var args TaskSpec
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		// The wire schema requires a stable caller-selected task ID. The core
		// store may generate an ID for trusted in-process callers, but the MCP
		// boundary must enforce the schema it advertises so clients and server
		// cannot disagree about the request contract.
		if args.ID == "" {
			return nil, fmt.Errorf("%w: task ID is required", ErrInvalid)
		}
		return dispatch(func() (any, error) { return a.controller.CreateTask(args) })
	case "lifecycle.task.read":
		var args struct {
			ID string `json:"id"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		return dispatch(func() (any, error) { return a.controller.Task(args.ID) })
	case "lifecycle.task.list", "lifecycle.task.ready":
		var args struct {
			ProjectID string `json:"project_id"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		if name == "lifecycle.task.list" {
			return dispatch(func() (any, error) { return a.controller.Tasks(args.ProjectID) })
		}
		return dispatch(func() (any, error) { return a.controller.Ready(args.ProjectID) })
	case "lifecycle.task.acquire":
		var args acquireArguments
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		ttl, err := args.ttl()
		if err != nil {
			return nil, err
		}
		return dispatch(func() (any, error) { return a.controller.Acquire(args.TaskID, ttl) })
	case "lifecycle.task.heartbeat":
		var args leaseArguments
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		ttl, err := args.ttl()
		if err != nil {
			return nil, err
		}
		return dispatch(func() (any, error) {
			return a.controller.Heartbeat(Lease{TaskID: args.TaskID, Owner: a.controller.Owner(), Version: args.Version}, ttl)
		})
	case "lifecycle.task.checkpoint":
		var args checkpointArguments
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		return dispatch(func() (any, error) {
			return a.controller.Checkpoint(Lease{TaskID: args.TaskID, Owner: a.controller.Owner(), Version: args.Version}, args.State, []byte(args.Payload))
		})
	case "lifecycle.task.recover_expired":
		var args struct{}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		return dispatch(func() (any, error) { return a.controller.RecoverExpired() })
	default:
		return nil, errors.New("unknown lifecycle tool")
	}
}

type leaseArguments struct {
	TaskID     string `json:"task_id"`
	Version    uint64 `json:"version,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

// acquireArguments intentionally omits the lease version. Acquisition creates
// the version; only heartbeat and checkpoint requests may present the version
// returned by that acquisition. Keeping a separate wire type makes the strict
// MCP decoder agree with the tools/list schema instead of accepting a field
// that has no meaning for acquisition.
type acquireArguments struct {
	TaskID     string `json:"task_id"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

func (a acquireArguments) ttl() (time.Duration, error) {
	return boundedLeaseTTL(a.TTLSeconds)
}

func (a leaseArguments) ttl() (time.Duration, error) {
	return boundedLeaseTTL(a.TTLSeconds)
}

func boundedLeaseTTL(seconds int64) (time.Duration, error) {
	const maxTTLSeconds = int64(maxLease / time.Second)
	if seconds <= 0 || seconds > maxTTLSeconds {
		return 0, fmt.Errorf("%w: lease TTL seconds must be between 1 and %d", ErrInvalid, maxTTLSeconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

type checkpointArguments struct {
	TaskID  string    `json:"task_id"`
	Version uint64    `json:"version"`
	State   TaskState `json:"state"`
	Payload string    `json:"payload,omitempty"`
}

func lifecycleTools() []map[string]any {
	identityProperty := func() map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": maxIDLength}
	}
	nameProperty := func() map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": maxNameLength}
	}
	optionalIDProperty := func() map[string]any {
		return map[string]any{"type": "string", "maxLength": maxIDLength}
	}
	integerProperty := func(min int64, max *int64) map[string]any {
		property := map[string]any{"type": "integer", "minimum": min}
		if max != nil {
			property["maximum"] = *max
		}
		return property
	}
	maxTTLSeconds := int64(maxLease / time.Second)
	tool := func(name, description string, readOnly, destructive, idempotent bool, properties map[string]any, required ...string) map[string]any {
		return map[string]any{
			"name":        name,
			"description": description,
			"inputSchema": objectSchema(properties, required...),
			"annotations": map[string]any{
				"title":           description,
				"readOnlyHint":    readOnly,
				"destructiveHint": destructive,
				"idempotentHint":  idempotent,
				"openWorldHint":   false,
			},
		}
	}
	return []map[string]any{
		tool("lifecycle.project.create", "Create an isolated lifecycle project", false, false, false, map[string]any{"id": identityProperty(), "name": nameProperty()}, "id", "name"),
		tool("lifecycle.project.archive", "Archive a lifecycle project", false, true, true, map[string]any{"id": identityProperty()}, "id"),
		tool("lifecycle.project.read", "Read a lifecycle project", true, false, true, map[string]any{"id": identityProperty()}, "id"),
		tool("lifecycle.task.create", "Create an idempotent DAG task", false, false, false, map[string]any{"id": identityProperty(), "project_id": identityProperty(), "dependencies": map[string]any{"type": "array", "maxItems": maxTaskDependencies, "items": identityProperty()}, "idempotency_key": optionalIDProperty()}, "id", "project_id"),
		tool("lifecycle.task.read", "Read a lifecycle task", true, false, true, map[string]any{"id": identityProperty()}, "id"),
		tool("lifecycle.task.list", "List tasks in a project", true, false, true, map[string]any{"project_id": identityProperty()}, "project_id"),
		tool("lifecycle.task.ready", "List deterministically ready tasks", true, false, true, map[string]any{"project_id": identityProperty()}, "project_id"),
		tool("lifecycle.task.acquire", "Acquire a task lease for the authenticated principal", false, false, false, map[string]any{"task_id": identityProperty(), "ttl_seconds": integerProperty(1, &maxTTLSeconds)}, "task_id", "ttl_seconds"),
		tool("lifecycle.task.heartbeat", "Extend the authenticated principal's task lease", false, false, false, map[string]any{"task_id": identityProperty(), "version": integerProperty(1, nil), "ttl_seconds": integerProperty(1, &maxTTLSeconds)}, "task_id", "version", "ttl_seconds"),
		tool("lifecycle.task.checkpoint", "Record bounded progress for the authenticated principal's lease", false, true, false, map[string]any{"task_id": identityProperty(), "version": integerProperty(1, nil), "state": map[string]any{"type": "string", "minLength": 1, "enum": []string{string(TaskRunning), string(TaskCompleted), string(TaskFailed), string(TaskCancelled)}}, "payload": map[string]any{"type": "string", "maxLength": maxPayloadBytes}}, "task_id", "version", "state"),
		tool("lifecycle.task.recover_expired", "Explicitly recover expired leases without executing tasks", false, true, false, nil),
	}
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	// JSON Schema requires `required`, when present, to be an array. Keep the
	// no-argument tool schema valid instead of encoding an omitted variadic
	// argument as JSON null.
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}

func knownLifecycleTool(name string) bool {
	for _, tool := range lifecycleTools() {
		if tool["name"] == name {
			return true
		}
	}
	return false
}

func decodeArguments(raw json.RawMessage, dst any) error {
	// The enclosing MCP request is already bounded in HandleContext. Repeat the
	// bound here so direct helper use cannot turn argument parsing into an
	// unbounded resource path or weaken the documented wire limit.
	if len(raw) > maxMCPRequestBytes {
		return fmt.Errorf("%w: tool arguments exceed %d bytes", ErrInvalid, maxMCPRequestBytes)
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if err := decodeStrictObject(raw, dst); err != nil {
		// Tool argument failures are data-contract errors, not internal
		// failures. Preserve the bounded parser detail for the authenticated
		// caller while making the wire error code stable.
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// encoding/json accepts an explicit JSON null for slices, strings, and
	// numeric fields by assigning their zero value. Every advertised lifecycle
	// tool property has a non-null JSON Schema type, so accepting that
	// normalization would make the wire contract differ between clients and the
	// server. Omitted optional fields remain valid; explicit null is not.
	if err := rejectExplicitNullObjectMembers(raw); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

func rejectExplicitNullObjectMembers(raw []byte) error {
	// This helper is reached through decodeArguments on the wire path, but keep
	// its direct MCP boundary aligned with the argument decoder as well.
	if len(raw) > maxMCPRequestBytes {
		return ErrMCPRequestTooLarge
	}
	var fields map[string]json.RawMessage
	if err := decodeStrictJSON(raw, &fields); err != nil {
		return err
	}
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("field %q must not be null", name)
		}
	}
	return nil
}

// validateInitializeParams keeps protocol negotiation explicit. A client may
// omit params, or omit protocolVersion inside params, for compatibility with
// older in-process callers. When it supplies a protocolVersion, the adapter
// validates the standard metadata containers as objects before claiming the
// negotiated wire contract. Capability contents belong to the MCP transport
// rather than the task store, so their object members remain opaque here.
func validateInitializeParams(raw json.RawMessage) error {
	// HandleContext bounds the complete request before reaching this helper,
	// but keep the protocol-parameter boundary safe for direct and future
	// internal callers too.
	if len(raw) > maxMCPRequestBytes {
		return ErrMCPRequestTooLarge
	}
	if len(raw) == 0 {
		return nil
	}
	var params struct {
		ProtocolVersion json.RawMessage `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ClientInfo      json.RawMessage `json:"clientInfo"`
	}
	if err := decodeStrictObject(raw, &params); err != nil {
		return err
	}
	versionSupplied := len(params.ProtocolVersion) > 0
	if versionSupplied {
		if len(params.ProtocolVersion) > maxMCPProtocolVersionBytes {
			return errors.New("protocolVersion exceeds limit")
		}
		var version string
		if err := json.Unmarshal(params.ProtocolVersion, &version); err != nil || version == "" {
			return errors.New("protocolVersion must be a non-empty string")
		}
		if version != MCPProtocolVersion {
			return fmt.Errorf("protocol version %q is not supported", version)
		}
	}
	// Omitting the version remains compatible with older trusted callers, but
	// metadata that is present must still have the MCP object shape. Otherwise
	// the compatibility path would accept null/array/string capability claims
	// that the versioned path rejects, leaving clients and intermediaries with
	// different interpretations of the same initialize request.
	if versionSupplied || len(params.Capabilities) > 0 {
		if err := validateInitializeObject("capabilities", params.Capabilities); err != nil {
			return err
		}
	}
	if versionSupplied || len(params.ClientInfo) > 0 {
		if err := validateInitializeObject("clientInfo", params.ClientInfo); err != nil {
			return err
		}
	}
	return nil
}

func validateInitializeObject(name string, raw json.RawMessage) error {
	if len(raw) > maxMCPRequestBytes {
		return ErrMCPRequestTooLarge
	}
	if len(raw) == 0 {
		return fmt.Errorf("%s must be an object", name)
	}
	var object map[string]json.RawMessage
	if err := decodeStrictJSON(raw, &object); err != nil || object == nil {
		return fmt.Errorf("%s must be an object", name)
	}
	return nil
}

// validateEmptyParams keeps methods without an implemented parameter schema
// from silently accepting a future or malformed parameter shape. Omitted
// params remain compatible with JSON-RPC callers; an explicitly supplied
// params value must be an empty object because this adapter does not advertise
// pagination or any ping options.
func validateEmptyParams(raw json.RawMessage) error {
	// The enclosing request is bounded already; repeat the MCP parameter bound
	// here so a direct helper call cannot bypass the request resource ceiling.
	if len(raw) > maxMCPRequestBytes {
		return ErrMCPRequestTooLarge
	}
	if len(raw) == 0 {
		return nil
	}
	var params struct{}
	return decodeStrictObject(raw, &params)
}

func decodeStrictObject(raw []byte, dst any) error {
	// This decoder is used only for MCP request objects. Keep its direct helper
	// boundary aligned with HandleContext and the specialized argument parser.
	if len(raw) > maxMCPRequestBytes {
		return ErrMCPRequestTooLarge
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("arguments must be an object")
	}
	return decodeStrictMCPObject(raw, dst)
}

// decodeStrictMCPObject adds exact JSON member-name matching to the ordinary
// strict decoder. encoding/json accepts case-insensitive matches for struct
// fields, but MCP schemas publish exact member names and
// additionalProperties=false. Rejecting case variants keeps clients,
// intermediaries, and this boundary on one request contract.
func decodeStrictMCPObject(raw []byte, dst any) error {
	// The specialized object decoder is itself an internal MCP boundary. Keep
	// direct and future callers from bypassing the request ceiling before the
	// exact-member and duplicate-key scans allocate their maps.
	if len(raw) > maxMCPRequestBytes {
		return ErrMCPRequestTooLarge
	}
	if err := rejectCaseVariantJSONMembers(raw, dst); err != nil {
		return err
	}
	return decodeStrictJSON(raw, dst)
}

func rejectCaseVariantJSONMembers(raw []byte, dst any) error {
	// decodeStrictMCPObject normally enforces this first, but keep the exact
	// member-name helper bounded on its own so a direct or future caller cannot
	// make json.Unmarshal allocate for input outside the MCP request ceiling.
	if len(raw) > maxMCPRequestBytes {
		return ErrMCPRequestTooLarge
	}
	typ := reflect.TypeOf(dst)
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == nil || typ.Kind() != reflect.Struct {
		return nil
	}
	fields := make(map[string]struct{})
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = field.Name
		}
		fields[name] = struct{}{}
	}
	if len(fields) == 0 {
		return nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return err
	}
	for member := range members {
		if _, exact := fields[member]; exact {
			continue
		}
		for expected := range fields {
			if strings.EqualFold(member, expected) {
				return fmt.Errorf("JSON member %q must use exact name %q", member, expected)
			}
		}
	}
	return nil
}

func decodeStrictJSON(raw []byte, dst any) error {
	// This decoder is shared by the MCP request path and persisted lifecycle
	// state. Keep the lowest shared boundary bounded before UTF-8 validation or
	// decoder setup so direct and future callers cannot bypass the 8 MiB state
	// resource ceiling.
	if len(raw) > maxStateBytes {
		return errLifecycleJSONTooLarge
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

// rejectDuplicateJSONKeys prevents parser differentials at the transport
// boundary. encoding/json otherwise accepts duplicate object members and keeps
// the last value, while another authenticated proxy or policy layer may keep
// the first one. Reject duplicates in every object before decoding into a Go
// value so all layers must agree on one unambiguous request.
func rejectDuplicateJSONKeys(raw []byte) error {
	// The scanner is shared by the 64 KiB MCP boundary and the 8 MiB persisted
	// state boundary. Callers normally enforce their narrower limit first, but
	// keep this lower helper bounded as well so a direct or future caller cannot
	// hand the decoder an arbitrarily large byte slice.
	if len(raw) > maxStateBytes {
		return errLifecycleJSONTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return scanJSONValue(dec)
}

func scanJSONValue(dec *json.Decoder) error {
	// The recursive scanner is normally reached with a decoder created by the
	// bounded JSON helpers, but keep the lowest helper safe for direct and
	// future in-process callers. A nil decoder must be a parser error rather
	// than a panic while the authenticated boundary is classifying input.
	if dec == nil {
		return errors.New("JSON decoder is unavailable")
	}
	return scanJSONValueAtDepth(dec, 0)
}

func scanJSONValueAtDepth(dec *json.Decoder, depth int) error {
	if dec == nil {
		return errors.New("JSON decoder is unavailable")
	}
	// Recursive calls only reach a depth in [0, maxMCPJSONDepth]. Reject an
	// invalid direct starting depth before scanning so a malformed integration
	// cannot bypass the nesting budget by supplying a negative value.
	if depth < 0 || depth > maxMCPJSONDepth {
		return errors.New("JSON nesting depth is invalid")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			if depth >= maxMCPJSONDepth {
				return errors.New("JSON nesting exceeds limit")
			}
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err := scanJSONValueAtDepth(dec, depth+1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
		case '[':
			if depth >= maxMCPJSONDepth {
				return errors.New("JSON nesting exceeds limit")
			}
			for dec.More() {
				if err := scanJSONValueAtDepth(dec, depth+1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
	}
	return nil
}

func validMCPID(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	// Request handling bounds the complete envelope, but response construction
	// and future internal callers may validate an ID independently. Keep that
	// scalar boundary from handing an oversized JSON string or number to the
	// decoder.
	if len(raw) > maxMCPRequestBytes {
		return false
	}
	// Keep the helper fail-closed when called independently of the enclosing
	// request decoder. The wire path already validates the complete request's
	// UTF-8, but a raw ID is an untrusted boundary in its own right.
	if !utf8.Valid(raw) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var id any
	if dec.Decode(&id) != nil {
		return false
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return false
	}
	switch id.(type) {
	case string:
		return true
	case json.Number:
		return validMCPIntegerID(id.(json.Number))
	default:
		return false
	}
}

// validMCPIntegerID keeps JSON-RPC request IDs on MCP's string-or-integer
// surface. json.Decoder represents fractional and exponent-form numbers as
// json.Number too, so accepting that type without checking its grammar would
// incorrectly admit IDs such as 1.5 and 1e0.
func validMCPIntegerID(value json.Number) bool {
	raw := string(value)
	if raw == "" || len(raw) > maxMCPRequestBytes {
		return false
	}
	index := 0
	if raw[0] == '-' {
		index++
		if index == len(raw) {
			return false
		}
	}
	if raw[index] == '0' {
		return index+1 == len(raw)
	}
	if raw[index] < '1' || raw[index] > '9' {
		return false
	}
	for index++; index < len(raw); index++ {
		if raw[index] < '0' || raw[index] > '9' {
			return false
		}
	}
	return true
}

func toolResult(value any, err error) mcpToolResult {
	if err != nil {
		code, message := mcpToolError(err)
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: message}}, IsError: true, StructuredContent: map[string]string{"code": code, "message": message}}
	}
	raw, marshalErr := marshalBoundedJSON(value, maxMCPResponseBytes)
	if marshalErr != nil {
		// A lifecycle value is normally made only from validated store data, but
		// keep the MCP boundary safe if a future controller or integration returns
		// a value that encoding/json cannot represent. Do not expose the marshal
		// diagnostic or let it turn a successful tool call into a transport error.
		const message = "lifecycle operation failed"
		return mcpToolResult{
			Content:           []mcpContent{{Type: "text", Text: message}},
			IsError:           true,
			StructuredContent: map[string]string{"code": "INTERNAL", "message": message},
		}
	}
	var structured any
	if json.Unmarshal(raw, &structured) != nil || structured == nil {
		structured = map[string]any{"items": value}
	}
	if _, ok := structured.(map[string]any); !ok {
		structured = map[string]any{"items": structured}
	}
	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: string(raw)}}, IsError: false, StructuredContent: structured}
}

// marshalMCPToolResponse keeps a result that becomes too large only after MCP
// wrapping from escaping as a transport error. Successful controller values
// are represented twice in a tool result (content text and structured
// content), so a value can fit the per-value bound while the complete JSON-RPC
// response exceeds its aggregate bound. Return the same bounded redacted
// internal failure used for unencodable or overlarge controller values.
func marshalMCPToolResponse(id json.RawMessage, value any, err error) ([]byte, error) {
	response, marshalErr := marshalMCPResponse(id, toolResult(value, err), nil)
	if !errors.Is(marshalErr, ErrMCPResponseTooLarge) {
		return response, marshalErr
	}
	return marshalMCPResponse(id, mcpToolResult{
		Content:           []mcpContent{{Type: "text", Text: "lifecycle operation failed"}},
		IsError:           true,
		StructuredContent: map[string]string{"code": "INTERNAL", "message": "lifecycle operation failed"},
	}, nil)
}

// mcpToolError maps lifecycle outcomes to a stable, bounded wire vocabulary.
// Detailed messages are useful for expected request/ownership failures, but an
// unknown error may contain a local filesystem or dependency detail and must
// not cross the authenticated MCP boundary.
func mcpToolError(err error) (code, message string) {
	// errors.Is may invoke an integration-supplied Is/Unwrap method, and the
	// expected-error path below calls Error(). A malformed in-process error must
	// not turn the authenticated transport boundary into a process panic. Keep
	// the fallback deliberately generic so neither panic detail nor local error
	// text crosses the MCP surface.
	code, message = "INTERNAL", "lifecycle operation failed"
	defer func() {
		if recover() != nil {
			code, message = "INTERNAL", "lifecycle operation failed"
		}
	}()
	if boundedMCPErrorIs(err, ErrForbidden) {
		return "FORBIDDEN", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrNotFound) {
		return "NOT_FOUND", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrConflict) {
		return "CONFLICT", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrArchived) {
		return "ARCHIVED", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrLeaseHeld) {
		return "LEASE_HELD", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrLeaseExpired) {
		return "LEASE_EXPIRED", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrNotOwner) {
		return "NOT_OWNER", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrDependencies) {
		return "DEPENDENCIES_INCOMPLETE", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrTerminal) {
		return "TERMINAL", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrIdempotency) {
		return "IDEMPOTENCY_CONFLICT", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrClosed) {
		return "CLOSED", boundedMCPErrorMessage(err.Error())
	}
	if boundedMCPErrorIs(err, ErrInvalid) {
		return "INVALID_ARGUMENT", boundedMCPErrorMessage(err.Error())
	}
	return code, message
}

// boundedMCPErrorIs preserves the standard wrapped and joined error matching
// used by the lifecycle sentinels while bounding an integration-supplied error
// graph. The standard errors.Is traversal has no cycle or depth limit; a
// malformed Unwrap method must therefore not be allowed to hang this boundary.
// Panics from custom Is or Unwrap methods are treated as a non-match and the
// caller's generic INTERNAL fallback remains in force.
func boundedMCPErrorIs(err, target error) (matched bool) {
	defer func() {
		if recover() != nil {
			matched = false
		}
	}()
	if err == nil || target == nil {
		return false
	}
	targetType := reflect.TypeOf(target)
	targetComparable := targetType != nil && targetType.Comparable()
	seen := make(map[error]struct{})
	stack := []error{err}
	visited := 0
	for len(stack) > 0 && visited < maxMCPErrorChainNodes {
		visited++
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		if current == nil {
			continue
		}
		currentType := reflect.TypeOf(current)
		if currentType != nil && currentType.Comparable() {
			if _, ok := seen[current]; ok {
				continue
			}
			seen[current] = struct{}{}
			if targetComparable && current == target {
				return true
			}
		}
		if matcher, ok := current.(interface{ Is(error) bool }); ok && matcher.Is(target) {
			return true
		}
		switch unwrapped := current.(type) {
		case interface{ Unwrap() error }:
			if next := unwrapped.Unwrap(); next != nil {
				stack = append(stack, next)
			}
		case interface{ Unwrap() []error }:
			children := unwrapped.Unwrap()
			for index := len(children) - 1; index >= 0 && len(stack) < maxMCPErrorChainNodes; index-- {
				if children[index] != nil {
					stack = append(stack, children[index])
				}
			}
		}
	}
	return false
}

// boundedMCPErrorMessage keeps expected lifecycle/parser detail useful without
// allowing untrusted request text to consume the complete response budget. It
// normalizes malformed UTF-8 while scanning only through the bounded prefix;
// this avoids materializing an arbitrarily large replacement string for a
// direct in-process error source. The cut is adjusted to a UTF-8 boundary so
// the MCP response remains valid text.
func boundedMCPErrorMessage(message string) string {
	const suffix = "..."
	contentLimit := maxMCPErrorMessageBytes - len(suffix)
	var output strings.Builder
	if len(message) < maxMCPErrorMessageBytes {
		output.Grow(len(message))
	}
	for len(message) > 0 {
		runeValue, size := utf8.DecodeRuneInString(message)
		if runeValue == utf8.RuneError && size == 1 {
			if output.Len()+len("\uFFFD") > contentLimit {
				output.WriteString(suffix)
				return output.String()
			}
			output.WriteString("\uFFFD")
			message = message[1:]
			continue
		}
		if output.Len()+size > contentLimit {
			output.WriteString(suffix)
			return output.String()
		}
		output.WriteString(message[:size])
		message = message[size:]
	}
	return output.String()
}

func marshalMCPResponse(id json.RawMessage, result any, rpcErr *mcpError) ([]byte, error) {
	// Keep response correlation fail-closed even if a future internal caller
	// bypasses HandleContext's request-envelope validation. An invalid ID cannot
	// be correlated safely, so JSON-RPC requires the response to use null rather
	// than reflecting attacker-controlled JSON or returning a malformed response.
	if len(id) == 0 || !validMCPID(id) {
		id = json.RawMessage("null")
	}
	b, err := marshalBoundedJSON(mcpResponse{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr}, maxMCPResponseBytes)
	if err != nil {
		return nil, err
	}
	return b, nil
}
