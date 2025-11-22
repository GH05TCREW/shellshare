package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shellshare/pkg/config"
	"shellshare/pkg/shellshare"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "join":
			joinCmd(ctx, os.Args[2:])
			return
		case "serve":
			serveCmd(ctx, os.Args[2:])
			return
		case "list":
			listCmd(os.Args[2:])
			return
		case "help", "--help", "-h":
			usage()
			return
		}
	}
	hostCmd(ctx, os.Args[1:])
}

func usage() {
	fmt.Println(`ShellShare - minimal terminal sharing

Usage:
  shellshare [--server ws://localhost:7777/ws] [--name <label>] [--allow-write] [--session <id>] [--record <file>] [--forward-target host:port]
  shellshare join <session-id> [--server ws://localhost:7777/ws] [--user <name>] [--forward-listen :PORT]
  shellshare serve [--addr :7777]
  shellshare list [--server ws://localhost:7777/ws]

Options:
  --session <id>         Custom session ID instead of auto-generated
  --name <label>         Session label shown to guests
  --allow-write          Allow guests to type (default: read-only)
  --record <file>        Record session output to file
  --forward-target <hp>  Expose local service to guests (host:port)
  --forward-listen <p>   Guest: bind forwarded port locally (:PORT)`)
}

func hostCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("host", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config file (default ~/.shellshare/config.toml)")
	server := fs.String("server", "", "signaling server websocket URL")
	name := fs.String("name", "", "session label shown to guests")
	allowWrite := fs.Bool("allow-write", false, "allow guests to type")
	readOnly := fs.Bool("read-only", false, "force guests to read-only mode")
	forwardTarget := fs.String("forward-target", "", "expose local service to guests (host:port)")
	recordPath := fs.String("record", "", "record session output to file")
	session := fs.String("session", "", "custom session id instead of generated")
	fs.Parse(args)

	cfg, _ := config.Load(*cfgPath)
	if *server != "" {
		cfg.SignalingURL = *server
	}
	if *name != "" {
		cfg.Name = *name
	}
	// allow-write overrides read-only. If neither supplied, default is read-only.
	cfg.AllowWrite = *allowWrite
	cfg.ReadOnly = *readOnly || !cfg.AllowWrite
	cfg.ForwardTarget = *forwardTarget
	cfg.ForwardListen = ""
	if *recordPath != "" {
		cfg.RecordPath = *recordPath
	}

	if err := shellshare.HostSession(ctx, cfg, *session); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func joinCmd(ctx context.Context, args []string) {
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	sessionID := args[0]
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config file (default ~/.shellshare/config.toml)")
	server := fs.String("server", "", "signaling server websocket URL")
	user := fs.String("user", "", "preferred handle shown to host")
	forwardListen := fs.String("forward-listen", "", "listen address to expose host forward target locally (e.g. :8080)")
	fs.Parse(args[1:])

	cfg, _ := config.Load(*cfgPath)
	if *server != "" {
		cfg.SignalingURL = *server
	}
	cfg.ForwardListen = *forwardListen
	if err := shellshare.JoinSession(ctx, cfg, sessionID, *user); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func serveCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":7777", "listen address")
	fs.Parse(args)

	if err := shellshare.ServeSignaling(ctx, *addr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func listCmd(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	server := fs.String("server", "ws://localhost:7777/ws", "signaling server websocket URL")
	fs.Parse(args)
	sessions, err := shellshare.ListSessions(*server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(sessions) == 0 {
		fmt.Println("No active sessions.")
		return
	}
	for _, s := range sessions {
		fmt.Printf("%s (viewers: %d, started: %s)\n", s.ID, s.Guests, s.StartedAt.Format(time.RFC822))
	}
}
