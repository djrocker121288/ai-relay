package gateway

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/ai-relay/ai-relay/internal/protocol"
)

func rpcError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	write(w, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}

// toolResult keeps legacy object fields as additive extensions while presenting
// standard content and structuredContent to strict MCP clients.
func toolResult(value any, toolError *protocol.Error) map[string]any {
	if toolError != nil {
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": toolError.Message}}, "isError": true, "structuredContent": map[string]any{"code": toolError.Code, "message": toolError.Message}}
	}
	raw, _ := json.Marshal(value)
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil || object == nil {
		object = map[string]any{"items": value}
	}
	result := map[string]any{}
	for key, field := range object {
		result[key] = field
	}
	result["content"] = []any{map[string]any{"type": "text", "text": string(raw)}}
	result["structuredContent"] = object
	result["isError"] = false
	return result
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	c := s.controllerFromRequest(r)
	if c == nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	if !allowedMCPOrigin(r) {
		http.Error(w, "forbidden origin", 403)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method", 405)
		return
	}
	body, err := readRequestBody(r)
	if err != nil {
		http.Error(w, err.Error(), 413)
		return
	}
	if !json.Valid(body) {
		rpcError(w, nil, -32700, "Parse error")
		return
	}
	var q struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if json.Unmarshal(body, &q) != nil || q.JSONRPC != "2.0" || q.Method == "" {
		rpcError(w, nil, -32600, "Invalid Request")
		return
	}
	if len(q.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var id any
	if json.Unmarshal(q.ID, &id) != nil {
		rpcError(w, nil, -32600, "Invalid Request")
		return
	}
	switch id.(type) {
	case string, float64:
	default:
		rpcError(w, nil, -32600, "Invalid Request")
		return
	}
	var result any
	switch q.Method {
	case "initialize":
		result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "ai-relay", "version": "1.0.0"}}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = tools()
	case "tools/call":
		if err := validateToolCall(q.Params); err != nil {
			rpcError(w, q.ID, -32602, err.Error())
			return
		}
		value, callErr := s.call(q.Params, r, c)
		if callErr != nil && (callErr.Code == "UNKNOWN_TOOL" || callErr.Code == "INVALID_ARGUMENT") {
			rpcError(w, q.ID, -32602, callErr.Message)
			return
		}
		result = toolResult(value, callErr)
	default:
		rpcError(w, q.ID, -32601, "Method not found")
		return
	}
	write(w, map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
}

func validateToolCall(params json.RawMessage) error {
	var call struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if json.Unmarshal(params, &call) != nil || call.Name == "" {
		return fmt.Errorf("tools/call requires a tool name and object arguments")
	}
	for _, entry := range tools().(map[string]any)["tools"].([]any) {
		tool := entry.(map[string]any)
		if tool["name"] != call.Name {
			continue
		}
		schema := tool["inputSchema"].(map[string]any)
		required, _ := schema["required"].([]string)
		for _, key := range required {
			value, ok := call.Arguments[key]
			if !ok || value == nil {
				return fmt.Errorf("missing required argument %s", key)
			}
		}
		properties, _ := schema["properties"].(map[string]any)
		for key, value := range call.Arguments {
			property, ok := properties[key].(map[string]any)
			if !ok {
				continue
			}
			valid := true
			switch property["type"] {
			case "string":
				_, valid = value.(string)
			case "boolean":
				_, valid = value.(bool)
			case "object":
				_, valid = value.(map[string]any)
			case "integer":
				number, ok := value.(float64)
				valid = ok && number == math.Trunc(number)
			case "array":
				items, ok := value.([]any)
				valid = ok
				if ok {
					for _, item := range items {
						itemSchema, _ := property["items"].(map[string]any)
						itemType, _ := itemSchema["type"].(string)
						if itemType == "string" {
							_, valid = item.(string)
						} else if itemType == "object" {
							_, valid = item.(map[string]any)
						} else {
							valid = false
						}
						if !valid {
							break
						}
					}
				}
			}
			if !valid {
				return fmt.Errorf("invalid argument type for %s", key)
			}
		}
		return nil
	}
	return fmt.Errorf("Unknown tool: %s", call.Name)
}

func allowedMCPOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	for _, allowed := range strings.Split(os.Getenv("AI_RELAY_MCP_ALLOWED_ORIGINS"), ",") {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	return loopback && strings.EqualFold(parsed.Host, r.Host)
}
