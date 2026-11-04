package agentcore

// PlatformCapabilities lists operations implemented by the portable agent.
// Screen capture, input injection, USB and service management require native
// helpers which are not included in this release.
func PlatformCapabilities() []string {
	return []string{"exec", "jobs", "jobs.cancel", "jobs.stdin", "files"}
}
