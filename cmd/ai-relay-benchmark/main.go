package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ai-relay/ai-relay/internal/v2/benchmark"
)

type stringList []string

func (s *stringList) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	var args stringList
	name := flag.String("name", "", "model/runtime label")
	command := flag.String("command", "", "already-installed model command")
	capability := flag.String("capability", "coding", "capability under test")
	workdir := flag.String("workdir", ".", "trusted benchmark working directory")
	prompt := flag.String("prompt", "", "fixed non-secret benchmark prompt")
	resourceEvidence := flag.String("resource-evidence", "", "pre-collected host/resource evidence")
	ollamaURL := flag.String("ollama-url", "", "loopback Ollama origin; enables the no-pull HTTP adapter")
	model := flag.String("model", "", "already-installed Ollama model")
	numContext := flag.Int("num-context", 4096, "Ollama context size")
	numPredict := flag.Int("num-predict", 160, "maximum generated tokens")
	seed := flag.Int("seed", 42, "Ollama sampling seed")
	timeout := flag.Duration("timeout", 5*time.Minute, "hard benchmark timeout")
	maxOutput := flag.Int("max-output", 256*1024, "per-stream output limit")
	flag.Var(&args, "arg", "command argument before the prompt; repeatable")
	flag.Parse()

	var result benchmark.Result
	if *ollamaURL != "" {
		runner := benchmark.OllamaRunner{Endpoint: *ollamaURL, Timeout: *timeout, MaxOutput: *maxOutput, NumContext: *numContext, NumPredict: *numPredict, Seed: *seed, ResourceEvidence: *resourceEvidence}
		result = runner.Run(context.Background(), *name, *model, *capability, *prompt)
	} else {
		runner := benchmark.Runner{WorkingDir: *workdir, Timeout: *timeout, MaxOutput: *maxOutput, ResourceEvidence: *resourceEvidence}
		result = runner.Run(context.Background(), benchmark.Spec{Name: *name, Command: *command, Args: args, Capability: *capability}, *prompt)
	}
	encoded, err := result.JSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(encoded))
	if result.Status != "passed" {
		os.Exit(1)
	}
}
