// Package protocol defines the versioned, authenticated AI Relay wire protocol.
package protocol

const Version = "ai-relay/v1"
const LegacyVersion = "rli/v1"

// AcceptsVersion keeps already-installed agents interoperable during migration.
func AcceptsVersion(v string) bool { return v == Version || v == LegacyVersion }

type Request struct {
	Version   string `json:"version"`
	ID        string `json:"id"`
	DeviceID  string `json:"device_id"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Method    string `json:"method"`
	Params    any    `json:"params,omitempty"`
	Signature string `json:"signature"`
}
type Response struct {
	Version string `json:"version"`
	ID      string `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

// Command is delivered by the gateway to an outbound-connected agent.
type Command struct {
	JobID  string `json:"job_id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

// AgentMessage is the newline-delimited message exchanged on the persistent
// authenticated agent stream. Commands flow gateway -> agent and results,
// job events, and heartbeats flow agent -> gateway.
type AgentMessage struct {
	Kind    string         `json:"kind"`
	Command *Command       `json:"command,omitempty"`
	Result  *CommandResult `json:"result,omitempty"`
	Event   *JobEvent      `json:"event,omitempty"`
	Error   string         `json:"error,omitempty"`
	At      int64          `json:"at,omitempty"`
}

type JobEvent struct {
	JobID  string `json:"job_id"`
	Stream string `json:"stream,omitempty"`
	Data   string `json:"data,omitempty"`
	Done   bool   `json:"done,omitempty"`
	Exit   *int   `json:"exit,omitempty"`
}

type CommandResult struct {
	JobID  string `json:"job_id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Device struct {
	ID, Name, Platform, Arch string
	Online                   bool
	LastSeen                 int64
	Capabilities             []string
}
type ExecParams struct {
	Command        string            `json:"command"`
	Args           []string          `json:"args,omitempty"`
	CWD            string            `json:"cwd,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	Privileged     bool              `json:"privileged,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}
