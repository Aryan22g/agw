package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Inventory tracks what tools a server advertises, so a change is visible.
//
// The attack this exists for is the one the MCP threat literature keeps
// returning to: a server advertises benign tools, is approved, and later
// changes what those tools do or adds new ones. Nothing in the protocol makes
// that visible to the client, because tools/list is answered fresh each time
// and the client has nothing to compare against.
//
// Hashing the advertised set and recording it turns a silent redefinition
// into an evidence record with a before and an after.
type Inventory struct {
	mu    sync.Mutex
	byURL map[string]string // upstream -> digest
}

// NewInventory builds an empty inventory.
func NewInventory() *Inventory {
	return &Inventory{byURL: make(map[string]string)}
}

// ToolSet is what a server advertised at one moment.
type ToolSet struct {
	Digest string
	Names  []string
	Count  int
}

// Observe records a tools/list response and reports whether the advertised
// set changed since the last time this upstream answered.
//
// changed is false on the first observation: there is nothing to compare
// against, and reporting a change would make every fresh start look like an
// attack.
func (i *Inventory) Observe(upstream string, body []byte) (set ToolSet, changed bool, previous string, ok bool) {
	var resp listResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return ToolSet{}, false, "", false
	}
	if len(resp.Result.Tools) == 0 {
		return ToolSet{}, false, "", false
	}

	// The description and schema are hashed alongside the name deliberately.
	// A tool that keeps its name and changes what it claims to do, or what it
	// accepts, is exactly the redefinition worth catching -- and a
	// name-only digest would miss it entirely.
	entries := make([]string, 0, len(resp.Result.Tools))
	names := make([]string, 0, len(resp.Result.Tools))
	for _, t := range resp.Result.Tools {
		schema := strings.TrimSpace(string(t.InputSchema))
		entries = append(entries, fmt.Sprintf("%d:%s%d:%s%d:%s",
			len(t.Name), t.Name, len(t.Description), t.Description, len(schema), schema))
		names = append(names, t.Name)
	}
	sort.Strings(entries)
	sort.Strings(names)

	sum := sha256.Sum256([]byte(strings.Join(entries, "\x00")))
	digest := hex.EncodeToString(sum[:])

	set = ToolSet{Digest: digest, Names: names, Count: len(names)}

	i.mu.Lock()
	defer i.mu.Unlock()

	prev, seen := i.byURL[upstream]
	i.byURL[upstream] = digest

	if !seen {
		return set, false, "", true
	}
	return set, prev != digest, prev, true
}

// Digest returns the last observed digest for an upstream.
func (i *Inventory) Digest(upstream string) (string, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	d, ok := i.byURL[upstream]
	return d, ok
}
