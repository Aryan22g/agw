package gym

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Agent is the hostile workload. It speaks to the confinement proxy over a
// raw socket rather than through net/http's client, because several of the
// attacks are about the shape of the request itself -- an absolute URI that
// disagrees with the Host header, a CONNECT authority with no port, a request
// line that two parsers will read differently. A well-behaved HTTP client
// normalises exactly the things worth testing.
type Agent struct {
	// ProxyAddr is the confinement proxy's listener. In a real deployment the
	// agent does not get to choose this; it is the only route out.
	ProxyAddr string

	// World lets an episode look up where a service lives.
	World *World

	// Zone lets an episode make DNS hostile.
	Zone *Zone

	// Episode is the id of the episode currently running, echoed in a header
	// so the world's ledger can attribute a hit even when the destination is
	// ambiguous.
	Episode string

	// Timeout bounds any single attempt.
	Timeout time.Duration

	// Range gives episodes access to the running configuration: the registry,
	// for revocation, and the evidence sink they can break.
	Range *Range
}

func (a *Agent) timeout() time.Duration {
	if a.Timeout <= 0 {
		return 8 * time.Second
	}
	return a.Timeout
}

// Get performs an ordinary forward-proxy request: absolute URI in the request
// line, which is what a proxy expects.
func (a *Agent) Get(hostport, path string) Attempt {
	return a.Raw(fmt.Sprintf("GET http://%s%s HTTP/1.1\r\nHost: %s\r\nX-Gym-Episode: %s\r\nConnection: close\r\n\r\n",
		hostport, path, hostport, a.Episode))
}

// Post sends a body to a destination through the proxy. The exfiltration
// episodes use this to move a canary.
func (a *Agent) Post(hostport, path, body string) Attempt {
	return a.Raw(fmt.Sprintf(
		"POST http://%s%s HTTP/1.1\r\nHost: %s\r\nX-Gym-Episode: %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		hostport, path, hostport, a.Episode, len(body), body))
}

// GetWithHost sends an absolute URI naming one host and a Host header naming
// another. If the two are ever allowed to diverge, the destination that was
// authorized and the destination that was served are different machines.
func (a *Agent) GetWithHost(uriHost, headerHost, path string) Attempt {
	return a.Raw(fmt.Sprintf("GET http://%s%s HTTP/1.1\r\nHost: %s\r\nX-Gym-Episode: %s\r\nConnection: close\r\n\r\n",
		uriHost, path, headerHost, a.Episode))
}

// Raw writes an exact request to the proxy and reads the response.
func (a *Agent) Raw(request string) Attempt {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", a.ProxyAddr, a.timeout())
	if err != nil {
		return Attempt{Err: err, Latency: time.Since(start)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(a.timeout()))

	if _, err := io.WriteString(conn, request); err != nil {
		return Attempt{Err: err, Latency: time.Since(start)}
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return Attempt{Err: err, Latency: time.Since(start)}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	return Attempt{
		Reached:     resp.StatusCode < 400,
		Status:      resp.StatusCode,
		ProxyReason: resp.Header.Get("X-AGW-Reason"),
		Body:        string(body),
		Latency:     time.Since(start),
	}
}

// Connect opens a CONNECT tunnel and, if it is established, sends one HTTP
// request through it.
//
// The authority in the CONNECT line and the Host header of the tunnelled
// request are separate arguments on purpose: inside a tunnel the proxy has
// committed to a destination and stops looking, so what the agent sends next
// is the question.
func (a *Agent) Connect(authority, innerHost, path string) Attempt {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", a.ProxyAddr, a.timeout())
	if err != nil {
		return Attempt{Err: err, Latency: time.Since(start)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(a.timeout()))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		return Attempt{Err: err, Latency: time.Since(start)}
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return Attempt{Err: err, Latency: time.Since(start)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return Attempt{
			Status:      resp.StatusCode,
			ProxyReason: resp.Header.Get("X-AGW-Reason"),
			Body:        string(body),
			Latency:     time.Since(start),
		}
	}

	// Tunnel established. Speak plain HTTP inside it -- the gym's world is
	// cleartext, so the tunnel carries a request the destination can serve
	// and the ledger can see.
	if innerHost == "" {
		return Attempt{Reached: true, Status: 200, Note: "tunnel established, unused", Latency: time.Since(start)}
	}
	if _, err := fmt.Fprintf(conn,
		"GET %s HTTP/1.1\r\nHost: %s\r\nX-Gym-Episode: %s\r\nConnection: close\r\n\r\n",
		path, innerHost, a.Episode); err != nil {
		return Attempt{Status: 200, Err: err, Latency: time.Since(start)}
	}

	inner, err := http.ReadResponse(br, nil)
	if err != nil {
		return Attempt{Status: 200, Err: err, Note: "tunnel open, inner request failed", Latency: time.Since(start)}
	}
	defer inner.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(inner.Body, 64<<10))

	return Attempt{
		Reached: true,
		Status:  inner.StatusCode,
		Body:    string(body),
		Note:    "tunnelled",
		Latency: time.Since(start),
	}
}

// ConnectHold opens a tunnel and keeps it open, returning the connection so an
// episode can revoke the workload underneath it and see what happens to
// traffic already in flight.
func (a *Agent) ConnectHold(authority string) (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("tcp", a.ProxyAddr, a.timeout())
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, nil, fmt.Errorf("gym: tunnel refused with %d (%s)", resp.StatusCode, resp.Header.Get("X-AGW-Reason"))
	}
	return conn, br, nil
}

// readInner reads one HTTP response from an already-established tunnel.
func readInner(br *bufio.Reader) Attempt {
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return Attempt{Err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	return Attempt{Reached: resp.StatusCode < 400, Status: resp.StatusCode, Body: string(body)}
}

// DirectTo bypasses the proxy entirely and dials a destination.
//
// In a correct deployment this cannot happen: the workload has no route to
// anything but the proxy, and that is established by the network rather than
// by the workload's cooperation. The episodes that use it declare
// CapNetworkBoundary, so they only run where such a boundary exists -- on an
// ordinary developer machine they would all succeed and mean nothing.
//
// The short timeout is deliberate. Under real isolation these attempts do not
// get refused, they hang: there is no route and nothing to send an RST, so the
// SYN goes nowhere. Waiting the full connect timeout on every probe would make
// a correct result the slowest one.
func (a *Agent) DirectTo(host string, port int, path string) Attempt {
	start := time.Now()
	target := net.JoinHostPort(host, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return Attempt{Err: err, Note: "no route to " + target, Latency: time.Since(start)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nX-Gym-Episode: direct:%s\r\nConnection: close\r\n\r\n",
		path, host, a.Episode)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		// A connection that opened and then produced nothing usable still
		// means a route exists, which is the finding. Say so rather than
		// reporting it as a refusal.
		return Attempt{
			Reached: true, Err: err,
			Note:    "TCP connection to " + target + " succeeded without the proxy",
			Latency: time.Since(start),
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return Attempt{
		Reached: true, Status: resp.StatusCode, Body: string(body),
		Note:    "reached " + target + " without passing through the enforcement point",
		Latency: time.Since(start),
	}
}

// Steal fetches a canary from a sensitive service, through the proxy.
// It returns the token if the theft succeeded. Most of the time it will not,
// which is the point: the exfiltration episodes need a secret in hand, and
// the gym hands it to them directly when policy correctly refuses the fetch,
// so that "could not steal it" never masquerades as "could not exfiltrate it".
func (a *Agent) Steal() string {
	if s, ok := a.World.FindByKind(KindSecrets); ok {
		at := a.Get(s.Addr(), "/v1/secrets")
		if at.Reached {
			for token := range a.World.Canaries {
				if strings.Contains(at.Body, token) {
					return token
				}
			}
		}
	}
	return a.World.AnyCanary()
}
