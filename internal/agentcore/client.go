package agentcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ai-relay/ai-relay/internal/protocol"
	"github.com/ai-relay/ai-relay/internal/security"
	"io"
	"net/http"
	"time"
)

type Client struct {
	Gateway, DeviceID, Secret string
	HTTP                      *http.Client
	Core                      *Core
}

func (c *Client) send(ctx context.Context, method string, params any) (map[string]any, error) {
	id, e := security.Token(12)
	if e != nil {
		return nil, e
	}
	nonce, e := security.Token(18)
	if e != nil {
		return nil, e
	}
	q := protocol.Request{Version: protocol.Version, ID: id, DeviceID: c.DeviceID, Timestamp: time.Now().Unix(), Nonce: nonce, Method: method, Params: params}
	q.Signature = security.Sign(c.Secret, q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(params))
	b, _ := json.Marshal(q)
	req, e := http.NewRequestWithContext(ctx, "POST", security.GatewayEndpoint(c.Gateway, "v1/agent/"+map[string]string{"agent.poll": "poll", "agent.result": "result"}[method]), bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	resp, e := c.client().Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gateway poll: %s", resp.Status)
	}
	var out map[string]any
	e = json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(&out)
	return out, e
}
func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
func paramsBytes(v any) []byte { b, _ := json.Marshal(v); return b }
func (c *Client) Poll(ctx context.Context) (*protocol.Command, error) {
	out, e := c.send(ctx, "agent.poll", nil)
	if e != nil {
		return nil, e
	}
	if out["command"] == nil {
		return nil, nil
	}
	b, _ := json.Marshal(out["command"])
	var cmd protocol.Command
	return &cmd, json.Unmarshal(b, &cmd)
}
func (c *Client) Run(ctx context.Context) error {
	for {
		cmd, e := c.Poll(ctx)
		if e != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
				continue
			}
		}
		if cmd != nil {
			c.execute(ctx, cmd)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
func (c *Client) execute(ctx context.Context, cmd *protocol.Command) {
	var p protocol.ExecParams
	b, _ := json.Marshal(cmd.Params)
	_ = json.Unmarshal(b, &p)
	var result any
	var err error
	if cmd.Method == "agent.exec" {
		result, err = c.Core.Run(ctx, c.DeviceID, p.Command, p.Args, p.CWD, p.Env, p.Privileged)
	} else if cmd.Method == "agent.cancel" {
		err = c.Core.Cancel(cmd.JobID)
	} else if cmd.Method == "agent.stdin" {
		var x struct {
			Data string `json:"data"`
		}
		_ = json.Unmarshal(b, &x)
		err = c.Core.WriteStdin(cmd.JobID, []byte(x.Data))
	} else {
		err = fmt.Errorf("unsupported method %s", cmd.Method)
	}
	cr := protocol.CommandResult{JobID: cmd.JobID, Result: result}
	if err != nil {
		cr.Error = err.Error()
	}
	// Keep the result until delivery succeeds; every retry gets a fresh signature.
	for {
		if _, err := c.send(ctx, "agent.result", cr); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
