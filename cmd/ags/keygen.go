package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/sdks/go/agentgw/keystore"
)

// runKeygen generates an agent keypair and writes it to a keystore file.
func runKeygen(args []string) error {
	fs := flagSet("keygen")
	var (
		tenant  = fs.String("tenant", "", "tenant id this agent belongs to")
		agent   = fs.String("agent", "", "agent id")
		out     = fs.String("out", "", "keystore path (default ~/.ags/credentials.json)")
		gateway = fs.String("gateway", "", "gateway base URL to record in the keystore")
		stdout  = fs.Bool("print", false, "print the keypair to stdout instead of writing a file")
	)
	_ = fs.Parse(args)

	if err := mustAbsent(*tenant, "tenant"); err != nil {
		return err
	}
	if err := mustAbsent(*agent, "agent"); err != nil {
		return err
	}

	kp, err := keys.Generate()
	if err != nil {
		return err
	}

	jwk, err := keys.PublicKeyToJWK(kp.PublicKey)
	if err != nil {
		return err
	}

	rec := keystore.Record{
		TenantID:   *tenant,
		AgentID:    *agent,
		KeyID:      kp.KeyID,
		PrivateKey: keys.EncodePrivateKey(kp.PrivateKey),
		PublicKey:  base64.StdEncoding.EncodeToString(kp.PublicKey),
		CreatedAt:  time.Now().UTC(),
		GatewayURL: *gateway,
	}

	if *stdout {
		return json.NewEncoder(os.Stdout).Encode(rec)
	}

	store, err := keystore.NewFileStore(*out)
	if err != nil {
		return err
	}
	if err := store.Save(rec); err != nil {
		return err
	}

	// The public half is what a verifier needs. Print it so the operator can
	// copy it without opening the file that holds the private key.
	jwkJSON, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return err
	}

	fmt.Printf("Key written to %s (mode 0600)\n\n", store.Path())
	fmt.Printf("  tenant : %s\n", *tenant)
	fmt.Printf("  agent  : %s\n", *agent)
	fmt.Printf("  key id : %s\n\n", kp.KeyID)
	fmt.Printf("Give this public key (JWK) to whatever verifies this agent's AGS1 requests:\n\n%s\n", jwkJSON)

	return nil
}

// runThumbprint derives an AGS1 key id from a base64 public key.
func runThumbprint(args []string) error {
	fs := flagSet("thumbprint")
	pub := fs.String("public-key", "", "base64-encoded Ed25519 public key")
	_ = fs.Parse(args)

	if err := mustAbsent(*pub, "public-key"); err != nil {
		return err
	}

	key, err := keys.DecodePublicKey(*pub)
	if err != nil {
		return err
	}
	id, err := keys.KeyID(key)
	if err != nil {
		return err
	}

	fmt.Println(id)
	return nil
}
