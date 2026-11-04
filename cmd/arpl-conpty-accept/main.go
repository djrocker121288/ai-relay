package main

import (
	"fmt"
	"os"

	"github.com/ai-relay/ai-relay/internal/arpl"
)

func main() {
	if err := arpl.RunConPTYAcceptance(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("ARPL ConPTY acceptance passed")
}
