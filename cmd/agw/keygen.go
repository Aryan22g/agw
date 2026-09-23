package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
)

// runKeygen writes the Ed25519 key that signs evidence checkpoints.
//
// This key is what stops a whole-file forgery: anyone able to rewrite the
// evidence log can recompute every hash, but without this key they cannot
// produce checkpoints that pin the rewritten chain. It therefore belongs
// somewhere the proxy's own compromise does not reach -- a separate host, or
// a KMS -- and the file mode here is the minimum, not the goal.
func runKeygen(args []string) error {
	fs := flagSet("keygen")
	out := fs.String("out", "", "path to write the private key")
	pub := fs.String("pub", "", "path to write the public key (default: OUT.pub)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	if *pub == "" {
		*pub = *out + ".pub"
	}

	kp, err := keys.Generate()
	if err != nil {
		return err
	}

	if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(kp.PrivateKey)), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(*pub, []byte(base64.StdEncoding.EncodeToString(kp.PublicKey)), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	fmt.Printf("checkpoint key written\n")
	fmt.Printf("  private  %s  (mode 0600)\n", *out)
	fmt.Printf("  public   %s\n", *pub)
	fmt.Printf("  key id   %s\n", kp.KeyID)
	fmt.Printf("\nDistribute only the public key. Anyone holding it can verify\n")
	fmt.Printf("the evidence chain without any access to this deployment.\n")
	return nil
}
