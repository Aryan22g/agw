package netns

import "time"

// Refusal categories. These are the question an incident responder actually
// asks -- "did this workload try to reach cloud credentials", "did it try to
// pivot internally" -- rather than a flat count of blocked packets.
const (
	// CategoryMetadata is link-local space, where cloud instance metadata
	// endpoints live. A workload reaching here directly, rather than through
	// the proxy, has decided not to talk to us. It is the single
	// highest-signal refusal the system produces.
	CategoryMetadata = "metadata_endpoint"

	// CategoryPrivate is RFC1918 space: an attempt to pivot into the
	// network the deployment sits in.
	CategoryPrivate = "private_network"

	// CategoryOther is everything else aimed past the host, which in
	// practice means the public internet.
	CategoryOther = "external"

	// CategoryHostPort is the host itself on a port other than the proxy's.
	CategoryHostPort = "host_service"
)

// RefusalCounts is a snapshot of what the firewall has refused.
type RefusalCounts struct {
	Metadata uint64
	Private  uint64
	Other    uint64
	HostPort uint64
}

// Total returns the sum across categories.
func (c RefusalCounts) Total() uint64 {
	return c.Metadata + c.Private + c.Other + c.HostPort
}

// ByCategory renders the counts keyed by category constant.
func (c RefusalCounts) ByCategory() map[string]uint64 {
	return map[string]uint64{
		CategoryMetadata: c.Metadata,
		CategoryPrivate:  c.Private,
		CategoryOther:    c.Other,
		CategoryHostPort: c.HostPort,
	}
}

// Refusal reports newly refused packets in one category.
//
// Counters are used rather than per-packet logging because per-packet logging
// on Linux means either /dev/kmsg -- which is unreadable inside a container,
// shared between tenants, and lossy under rate limiting -- or an nflog netlink
// listener, which is a great deal of protocol code for detail this does not
// need. A workload that tried to reach cloud metadata eleven times is the
// finding; which ephemeral source port each attempt used is not.
type Refusal struct {
	Sandbox  string
	Category string

	// Delta is how many packets were refused since the previous observation.
	Delta uint64

	// Total is the running count for this category.
	Total uint64

	At time.Time
}

// RefusalHandler receives refusals as they are observed. It runs on the
// watcher's goroutine and must not block.
type RefusalHandler func(Refusal)
