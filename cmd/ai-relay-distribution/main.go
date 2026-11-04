package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/ai-relay/ai-relay/internal/distribution"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8787", "loopback listen address; put an authenticated TLS tunnel in front when publishing")
	manifests := flag.String("manifests", "./manifests", "signed update manifest directory")
	artifacts := flag.String("artifacts", "./artifacts", "reserved artifact directory for deployment packaging")
	data := flag.String("data", "./distribution-data", "telemetry/report JSONL directory")
	tunnelProvider := flag.String("tunnel-provider", os.Getenv("AI_RELAY_TUNNEL_PROVIDER"), "operator-owned tunnel provider")
	tunnelHostname := flag.String("tunnel-hostname", os.Getenv("AI_RELAY_TUNNEL_HOSTNAME"), "public tunnel hostname")
	tunnelTarget := flag.String("tunnel-target", os.Getenv("AI_RELAY_TUNNEL_TARGET"), "loopback HTTP target served by the tunnel")
	tunnelConfig := flag.String("tunnel-config", os.Getenv("AI_RELAY_TUNNEL_CONFIG"), "provider config path; credentials are never read or logged")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("distribution service must bind to a loopback address")
	}
	for _, p := range []string{*manifests, *artifacts, *data} {
		if err := os.MkdirAll(p, 0700); err != nil {
			log.Fatal(err)
		}
	}
	tunnel, err := distribution.LoadTunnelConfig(func(key string) string {
		switch key {
		case "AI_RELAY_TUNNEL_PROVIDER":
			return *tunnelProvider
		case "AI_RELAY_TUNNEL_HOSTNAME":
			return *tunnelHostname
		case "AI_RELAY_TUNNEL_TARGET":
			return *tunnelTarget
		case "AI_RELAY_TUNNEL_CONFIG":
			return *tunnelConfig
		default:
			return ""
		}
	})
	if err != nil {
		log.Fatal(err)
	}
	s := &distribution.Service{ManifestDir: *manifests, ArtifactDir: *artifacts, DataDir: *data, Tunnel: tunnel}
	log.Printf("ai-relay distribution service on %s (%s)", *addr, s)
	log.Fatal(http.ListenAndServe(*addr, s.Routes()))
}
