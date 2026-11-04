package main

import (
	"flag"
	"fmt"
	"github.com/ai-relay/ai-relay/internal/gateway"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8743", "listen address")
	state := flag.String("state", "./state", "state directory")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(fmt.Errorf("invalid listen address: %w", err))
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		log.Fatal("gateway must bind to a loopback address; public ports are unsupported")
	}
	s, e := gateway.New(*state)
	if e != nil {
		log.Fatal(e)
	}
	if os.Getenv("AI_RELAY_MCP_TOKEN") == "" && os.Getenv("AI_RELAY_MCP_TOKEN_FILE") == "" && os.Getenv("RLI_MCP_TOKEN") == "" && os.Getenv("RLI_MCP_TOKEN_FILE") == "" {
		log.Print("WARNING: MCP token is unset; local access still requires a configured token")
	}
	log.Printf("ai-relay gateway %s on %s", *state, *addr)
	log.Fatal(http.ListenAndServe(*addr, s.Routes()))
}
