package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/xtls/xray-core/main/commands/base"
)

// cmdSingbox runs a complete sing-box config on the sing-box engine linked into this binary, so a
// desktop client needs no second binary for sing-box configs — the same engine that carries the
// "singbox" outbound runs them.
var cmdSingbox = &base.Command{
	UsageLine: "{{.Exec}} singbox [-test] -c config.json [-D dir]",
	Short:     "Run a sing-box config with the built-in sing-box engine",
	Long: `
Run a complete sing-box config with the sing-box engine built into this binary.

The -c flag names the config file; "-" reads it from standard input.

The -D flag sets the working directory, where the config's relative paths (cache files, rule sets)
are resolved.

The -test flag checks the config and exits without starting it.
	`,
}

var (
	singboxConfigPath = cmdSingbox.Flag.String("c", "", "sing-box config file, or - for standard input")
	singboxWorkDir    = cmdSingbox.Flag.String("D", "", "working directory")
	singboxTest       = cmdSingbox.Flag.Bool("test", false, "check the config and exit")
)

func init() {
	cmdSingbox.Run = executeSingbox
}

func executeSingbox(cmd *base.Command, args []string) {
	if err := runSingbox(); err != nil {
		fmt.Fprintln(os.Stderr, "sing-box:", err)
		os.Exit(23)
	}
}

func runSingbox() error {
	if *singboxConfigPath == "" {
		return fmt.Errorf("no config: use -c config.json")
	}
	var content []byte
	var err error
	if *singboxConfigPath == "-" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(*singboxConfigPath)
	}
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if *singboxWorkDir != "" {
		if err := os.MkdirAll(*singboxWorkDir, 0o700); err != nil {
			return fmt.Errorf("working directory: %w", err)
		}
		if err := os.Chdir(*singboxWorkDir); err != nil {
			return fmt.Errorf("working directory: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	defer cancel()
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, content)
	if err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if *singboxTest {
		instance.Close()
		fmt.Println("Configuration OK.")
		return nil
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	if err := instance.Start(); err != nil {
		instance.Close()
		return fmt.Errorf("start: %w", err)
	}
	fmt.Println("sing-box started")
	<-signals

	closed := make(chan struct{})
	go func() {
		instance.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		return fmt.Errorf("closing took too long")
	}
	return nil
}
