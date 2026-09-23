package auditcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Aryan22g/agw/internal/gateway/audit"
)

// followPoll is how often a followed log is checked for growth. Polling
// rather than filesystem notification keeps this portable and dependency-free,
// and a quarter second is below what a person watching a terminal notices.
var followPoll = 250 * time.Millisecond

// followStop, when closed, ends a follow. Tests use it; the command line ends
// a follow with Ctrl-C, which terminates the process.
var followStop chan struct{}

// follow prints matching records already in the log, then keeps printing new
// ones as they are appended.
//
// Only complete lines are decoded. The evidence sink writes through a buffer
// and flushes on group commit, so a reader can observe half a record; parsing
// it would print an error for a record that is, a moment later, perfectly
// valid.
func follow(path string, filter showFilter, print func(audit.Record)) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence log: %w", err)
	}
	defer f.Close()

	var (
		pending []byte
		offset  int64
		buf     = make([]byte, 64<<10)
	)

	for {
		n, err := f.Read(buf)
		if n > 0 {
			offset += int64(n)
			pending = append(pending, buf[:n]...)
			for {
				i := bytes.IndexByte(pending, '\n')
				if i < 0 {
					break
				}
				line := bytes.TrimSpace(pending[:i])
				pending = pending[i+1:]
				if len(line) == 0 || bytes.Contains(line, []byte(`"type":"checkpoint"`)) {
					continue
				}
				var rec audit.Record
				if json.Unmarshal(line, &rec) != nil {
					continue
				}
				if filter.match(rec) {
					print(rec)
				}
			}
			continue
		}
		if err != nil && err != io.EOF {
			return err
		}

		// At the end of what has been written. A log that got SHORTER was
		// truncated or replaced underneath us; saying so matters more than
		// carrying on, because in an evidence log that is itself an event.
		if info, statErr := os.Stat(path); statErr == nil && info.Size() < offset {
			fmt.Fprintf(os.Stderr, "\n%s shrank from %d to %d bytes while being followed: "+
				"it was truncated or replaced. Verify it before trusting it.\n", path, offset, info.Size())
			return &ExitError{Code: 2, Msg: "evidence log truncated while being followed"}
		}

		select {
		case <-followStop:
			return nil
		case <-time.After(followPoll):
		}
	}
}
