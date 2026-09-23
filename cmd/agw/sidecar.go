package main

import (
	"fmt"
	"strconv"

	"github.com/Aryan22g/agw/internal/confine/sidecar"
)

// runSidecarInit confines a workload that shares a network namespace with the
// proxy -- a Kubernetes pod, or `docker run --network container:NAME`.
//
// It runs once, as an init step with CAP_NET_ADMIN, and exits. After it only
// sockets owned by the proxy's UID can leave the namespace; everything else
// can reach the proxy on loopback and nothing more. The workload container
// must drop every capability, or it can remove the rules or take the proxy's
// UID. See internal/confine/sidecar.
func runSidecarInit(args []string) error {
	fs := flagSet("sidecar-init")
	var (
		proxyUID  = fs.Int("proxy-uid", 1337, "UID the proxy runs as; the only UID allowed to reach the network")
		proxyPort = fs.Int("proxy-port", 8080, "loopback port the proxy listens on")
		print     = fs.Bool("print", false, "print the nftables ruleset instead of applying it")
		extra     portFlags
	)
	fs.Var(&extra, "allow-loopback-port", "a further loopback port the workload may reach, e.g. agw mcp on 8900 (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := sidecar.Config{ProxyUID: *proxyUID, ProxyPort: *proxyPort, AllowLoopbackPorts: extra}
	if *print {
		rules, err := sidecar.Rules(cfg)
		if err != nil {
			return err
		}
		fmt.Print(rules)
		return nil
	}
	if err := sidecar.Apply(cfg); err != nil {
		return err
	}
	fmt.Printf("agw: sidecar confinement applied: only UID %d may leave this network namespace;\n", *proxyUID)
	fmt.Printf("agw: everything else may reach 127.0.0.1:%d (the proxy)", *proxyPort)
	for _, p := range extra {
		fmt.Printf(", :%d", p)
	}
	fmt.Println(" and nothing more.")
	fmt.Println("agw: the workload container must drop ALL capabilities, or it can undo this.")
	return nil
}

type portFlags []int

func (p *portFlags) String() string { return fmt.Sprint(*p) }
func (p *portFlags) Set(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil {
		return err
	}
	*p = append(*p, n)
	return nil
}
