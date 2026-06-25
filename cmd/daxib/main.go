// Command daxib is the agent-first Bitcoin CLI wallet.
//
// main() is intentionally tiny: it installs a SIGTERM/SIGINT-cancellable
// context so a killed container exits resumably, hands control to the cli
// frontend, and exits with the process code the exit-code registry returns. The
// version build-stamp is injected by -ldflags into internal/version (read there,
// not here). main reads nothing else.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/daxchain-io/daxib/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(cli.Execute(ctx))
}
