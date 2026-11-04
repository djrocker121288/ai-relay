# Architecture

The gateway is the policy/audit/MCP boundary. Agents are outbound-connected device principals. The implemented transport is a reconnect-safe signed `ai-relay/v1` long-poll/result channel; a non-loopback deployment should add TLS 1.3 and per-device client certificates. The gateway dispatches commands/jobs/files to an agent, which executes through native OS APIs and returns bounded results. Durable job state belongs in the gateway state directory; volatile process handles remain on the agent.

The current vertical slice intentionally keeps the HTTP request validation and portable executor independently testable. Protocol messages are JSON for debuggability; large files and terminal streams should use framed binary messages referenced by request IDs. Request IDs, timestamps, nonces, and event sequence numbers provide correlation and replay resistance.

## 2.0 hardware self-test

`cmd/ai-relay-selftest` performs read-only CPU, memory, NVIDIA, filesystem-capacity, and installed Ollama inventory probes. Ollama inventory runs `ollama list` only; it never pulls, deletes, overwrites, or changes a model. Missing optional probes are emitted as warnings and do not become synthetic capability claims. The JSON includes the detected storage path and available bytes so a supervisor can enforce a download headroom gate.

Profiles are selected with `-profile light|standard|performance`; an omitted value uses the deterministic recommendation. `server-custom` is an API-level option and must supply operator values validated against detected CPU, memory, GPU, and VRAM capacity. Built-in profiles reserve host capacity and remain bounded by the snapshot. The current 2.0 storage gate prevents model downloads when safe headroom is not established.

The P3 local action and benchmark contracts are documented in
[docs/2.0/TERMINAL.md](2.0/TERMINAL.md). They are additive v2 packages and do
not change the 1.x executor or deployed services.
