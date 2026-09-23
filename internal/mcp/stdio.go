package mcp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// maxStdioLine bounds one stdio message. MCP's stdio transport is one JSON
// message per line; a line longer than this is refused rather than buffered
// without limit.
const maxStdioLine = 16 << 20

// ServeStdio enforces policy on MCP's stdio transport.
//
// Most MCP servers people run are local subprocesses that speak JSON-RPC over
// stdin and stdout -- it is what desktop clients, IDEs and coding agents
// launch. An enforcement point that only fronted HTTP servers therefore did
// not reach most real deployments. This sits in the middle of the pipe:
//
//	client --stdin--> [ServeStdio] --serverIn--> server
//	client <-stdout-- [ServeStdio] <-serverOut-- server
//
// Client-to-server messages go through Admit; a refused one is answered
// directly and never reaches the server. Server-to-client messages pass
// through unchanged, and tools/list results are inspected on the way.
//
// It returns when either side closes. Closing the client's stream closes the
// server's stdin, which is how a stdio server is told to exit.
func (e *Enforcer) ServeStdio(ctx context.Context, clientIn io.Reader, clientOut io.Writer,
	serverIn io.WriteCloser, serverOut io.Reader) error {

	var outMu sync.Mutex
	toClient := func(line []byte) error {
		outMu.Lock()
		defer outMu.Unlock()
		if _, err := clientOut.Write(line); err != nil {
			return err
		}
		_, err := clientOut.Write([]byte{'\n'})
		return err
	}

	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)

	// server -> client
	go func() {
		serverDone <- eachLine(serverOut, func(line []byte) error {
			e.ObserveResponse(ctx, line, false)
			return toClient(line)
		})
	}()

	// client -> server
	go func() {
		err := eachLine(clientIn, func(line []byte) error {
			v := e.Admit(ctx, line)
			if v.Forward {
				_, err := serverIn.Write(append(append([]byte{}, line...), '\n'))
				return err
			}
			if v.Reply != nil {
				return toClient(v.Reply)
			}
			return nil
		})
		_ = serverIn.Close()
		clientDone <- err
	}()

	select {
	case err := <-serverDone:
		// The server is gone; nothing further can be answered.
		return err
	case err := <-clientDone:
		if err != nil {
			return err
		}
		// The client finished. Its stdin close has been passed on, and the
		// server's last responses may still be in flight: let them drain
		// rather than cutting them off, but do not wait forever on a server
		// that ignores end of input.
		select {
		case err := <-serverDone:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(StdioDrainTimeout):
			return nil
		}
	}
}

// StdioDrainTimeout bounds how long ServeStdio waits for a server to finish
// answering after the client has closed its side.
var StdioDrainTimeout = 5 * time.Second

// eachLine calls fn for every non-empty line, without the newline.
func eachLine(r io.Reader, fn func([]byte) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var buf []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if len(chunk) > 0 {
			if len(buf)+len(chunk) > maxStdioLine {
				return errors.New("mcp: stdio message exceeds the size limit")
			}
			buf = append(buf, chunk...)
		}
		if err != nil {
			if len(bytes.TrimSpace(buf)) > 0 {
				if ferr := fn(buf); ferr != nil {
					return ferr
				}
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
		if isPrefix {
			continue
		}
		if line := bytes.TrimSpace(buf); len(line) > 0 {
			if err := fn(line); err != nil {
				return err
			}
		}
		buf = buf[:0]
	}
}
