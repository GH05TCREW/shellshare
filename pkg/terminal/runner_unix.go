//go:build !windows
// +build !windows

package terminal

import (
	"context"
	"io"
	"os/exec"

	"github.com/creack/pty"
)

// Start runs the shell inside a PTY so interactive programs behave correctly.
func (r Runner) Start(ctx context.Context, outWriter io.Writer, localInput <-chan []byte, remoteInput <-chan []byte) error {
	cmd := exec.CommandContext(ctx, r.Command, r.Args...)
	
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()

	// Stream process output to caller.
	go io.Copy(outWriter, ptmx)

	// Feed local + remote input into the PTY master.
	go func() {
		for {
			select {
			case data, ok := <-localInput:
				if !ok {
					return
				}
				if len(data) > 0 {
					_, _ = ptmx.Write(data)
				}
			case data, ok := <-remoteInput:
				if !ok {
					return
				}
				if len(data) > 0 {
					_, _ = ptmx.Write(data)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return err
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-waitCh
		return ctx.Err()
	}
}
