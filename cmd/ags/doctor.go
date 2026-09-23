package main

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/sdks/go/agentgw/keystore"
)

// runDoctor diagnoses a local agent setup.
//
// Signature failures are famously opaque: the gateway can only say "invalid",
// because saying more would turn it into an oracle for which tenants and keys
// exist. That is right for the gateway and useless for the operator, so the
// diagnosis has to happen here, where the private key and local config are
// available.
func runDoctor(args []string) error {
	fs := flagSet("doctor")
	var (
		ksPath  = fs.String("keystore", "", "keystore path (default ~/.ags/credentials.json)")
		gateway = fs.String("gateway", "", "gateway base URL to probe")
	)
	_ = fs.Parse(args)

	var problems int
	check := func(label string, err error, hint string) {
		if err == nil {
			fmt.Printf("  [ok]   %s\n", label)
			return
		}
		problems++
		fmt.Printf("  [FAIL] %s\n         %v\n", label, err)
		if hint != "" {
			fmt.Printf("         fix: %s\n", hint)
		}
	}

	fmt.Println("Agent setup diagnosis")
	fmt.Println()

	// 1. Keystore presence and permissions.
	store, err := keystore.NewFileStore(*ksPath)
	if err != nil {
		return err
	}
	fmt.Printf("  keystore: %s\n\n", store.Path())

	record, loadErr := store.Load()
	check("keystore readable with safe permissions", loadErr,
		fmt.Sprintf("run 'ags keygen' or 'ags register', or 'chmod 600 %s'", store.Path()))
	if loadErr != nil {
		fmt.Printf("\n%d problem(s) found.\n", problems)
		return fmt.Errorf("cannot continue without a readable keystore")
	}

	// 2. Key material consistency: does the stored kid actually derive from
	// the stored private key?
	priv, err := keys.DecodePrivateKey(record.PrivateKey)
	check("private key decodes", err, "the keystore may be corrupt; re-register")

	if err == nil {
		// The stored key id must be the RFC 7638 thumbprint of the stored
		// key. A mismatch means the gateway will look up a credential this
		// key cannot sign for, which surfaces only as an opaque 401.
		derived, derr := keys.KeyID(priv.Public().(ed25519.PublicKey))
		if derr != nil {
			check("key id derivable", derr, "re-register this agent")
		} else if derived != record.KeyID {
			check("key id matches the stored key material",
				fmt.Errorf("keystore says %s but the key derives %s", record.KeyID, derived),
				"the keystore was edited or corrupted; re-register this agent")
		} else {
			check("key id matches the stored key material", nil, "")
		}

		// A proof round-trip exercises the exact code path registration uses.
		now := time.Now().UTC()
		proof, perr := keys.SignProof(priv, record.TenantID, record.AgentID, record.KeyID, now)
		if perr == nil {
			perr = keys.VerifyProof(priv.Public().(ed25519.PublicKey),
				record.TenantID, record.AgentID, record.KeyID, proof, now, now)
		}
		check("key can produce a valid proof of possession", perr,
			"the private key does not match the registered public key; re-register")
	}

	fmt.Printf("\n  tenant : %s\n", record.TenantID)
	fmt.Printf("  agent  : %s\n", record.AgentID)
	fmt.Printf("  key id : %s\n\n", record.KeyID)

	// 3. Clock skew against the gateway. A signature is only valid inside a
	// 300s window, so a drifting local clock produces requests that fail with
	// no obvious cause.
	target := *gateway
	if target == "" {
		target = record.GatewayURL
	}

	if target == "" {
		fmt.Println("  [skip] gateway checks (no -gateway and none recorded in the keystore)")
	} else {
		fmt.Printf("  gateway: %s\n\n", target)

		resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(target + "/healthz")
		check("gateway reachable", err, "check the URL, and that the gateway is running")
		if err == nil {
			defer resp.Body.Close()

			if dateHeader := resp.Header.Get("Date"); dateHeader != "" {
				serverTime, perr := http.ParseTime(dateHeader)
				if perr == nil {
					skew := time.Since(serverTime)
					if skew < 0 {
						skew = -skew
					}
					var skewErr error
					if skew > 60*time.Second {
						skewErr = fmt.Errorf("local clock differs from the gateway by %s; "+
							"signatures are only accepted within a 300s window",
							skew.Truncate(time.Second))
					}
					check(fmt.Sprintf("clock skew within tolerance (%s)", skew.Truncate(time.Second)),
						skewErr, "sync this host's clock with NTP")
				}
			}
		}
	}

	fmt.Println()
	if problems == 0 {
		fmt.Println("No problems found.")
		return nil
	}
	fmt.Printf("%d problem(s) found.\n", problems)
	os.Exit(1)
	return nil
}
