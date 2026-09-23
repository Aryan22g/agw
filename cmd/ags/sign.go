package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Aryan22g/agw/pkg/ags1/canonicalhttp"
	"github.com/Aryan22g/agw/pkg/ags1/httpmsig"
	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/sdks/go/agentgw/keystore"
)

// runSign signs a request and prints exactly what was signed.
//
// The signature base is the output that matters. When an SDK in another
// language fails to verify, comparing its base against this one localizes the
// disagreement to a single line, which is far faster than debugging a boolean
// "signature invalid".
func runSign(args []string) error {
	fs := flagSet("sign")
	var (
		method   = fs.String("method", "GET", "HTTP method")
		urlFlag  = fs.String("url", "", "absolute request URL")
		bodyFile = fs.String("body", "", "file containing the request body ('-' for stdin)")
		ctype    = fs.String("content-type", "application/json", "content type for a body-bearing request")
		keyFile  = fs.String("keystore", "", "keystore path (default ~/.ags/credentials.json)")
		showBase = fs.Bool("show-base", true, "print the signature base")
	)
	_ = fs.Parse(args)

	if err := mustAbsent(*urlFlag, "url"); err != nil {
		return err
	}

	store, err := keystore.NewFileStore(*keyFile)
	if err != nil {
		return err
	}
	rec, err := store.Load()
	if err != nil {
		return err
	}
	priv, err := keys.DecodePrivateKey(rec.PrivateKey)
	if err != nil {
		return err
	}

	var body []byte
	if *bodyFile != "" {
		if *bodyFile == "-" {
			body, err = io.ReadAll(os.Stdin)
		} else {
			body, err = os.ReadFile(*bodyFile)
		}
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}
	}

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(*method, *urlFlag, reader)
	if err != nil {
		return err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", *ctype)
	}

	res, err := httpmsig.Sign(httpmsig.SignInput{
		Request:    req,
		Body:       body,
		TenantID:   rec.TenantID,
		AgentID:    rec.AgentID,
		KeyID:      rec.KeyID,
		PrivateKey: priv,
	})
	if err != nil {
		return err
	}

	fmt.Println("# Request headers")
	for _, name := range []string{
		"X-Tenant-Id", "X-Agent-Id", "X-Request-Id",
		"X-Agent-Signature-Version", "Traceparent",
		"Content-Type", "Content-Digest",
		"Signature-Input", "Signature",
	} {
		if v := req.Header.Get(name); v != "" {
			fmt.Printf("%s: %s\n", name, v)
		}
	}

	if *showBase {
		fmt.Printf("\n# Signature base (%d bytes)\n%s\n", len(res.SignatureBase), res.SignatureBase)
	}

	fmt.Printf("\n# curl\ncurl -X %s %q \\\n", *method, *urlFlag)
	for _, name := range []string{
		"X-Tenant-Id", "X-Agent-Id", "X-Request-Id",
		"X-Agent-Signature-Version", "Traceparent",
		"Content-Type", "Content-Digest",
		"Signature-Input", "Signature",
	} {
		if v := req.Header.Get(name); v != "" {
			fmt.Printf("  -H %q \\\n", name+": "+v)
		}
	}
	if len(body) > 0 {
		fmt.Printf("  --data-binary %q\n", string(res.Body))
	} else {
		fmt.Println("  -i")
	}

	return nil
}

// runVerify checks a signed request against a public key.
//
// This is the conformance entry point: an SDK in any language can emit a
// signed request, and this command decides whether an AGS1 verifier accepts
// it.
func runVerify(args []string) error {
	fs := flagSet("verify")
	var (
		method    = fs.String("method", "GET", "HTTP method")
		urlFlag   = fs.String("url", "", "absolute request URL")
		bodyFile  = fs.String("body", "", "file containing the request body ('-' for stdin)")
		sigInput  = fs.String("signature-input", "", "Signature-Input header value")
		sig       = fs.String("signature", "", "Signature header value")
		pubKey    = fs.String("public-key", "", "base64-encoded Ed25519 public key")
		headerArg = fs.String("headers", "", "extra headers as 'Name: value' separated by newlines")
	)
	_ = fs.Parse(args)

	for name, v := range map[string]string{
		"url": *urlFlag, "signature-input": *sigInput,
		"signature": *sig, "public-key": *pubKey,
	} {
		if err := mustAbsent(v, name); err != nil {
			return err
		}
	}

	pub, err := keys.DecodePublicKey(*pubKey)
	if err != nil {
		return err
	}

	var body []byte
	if *bodyFile != "" {
		if *bodyFile == "-" {
			body, err = io.ReadAll(os.Stdin)
		} else {
			body, err = os.ReadFile(*bodyFile)
		}
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}
	}

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(*method, *urlFlag, reader)
	if err != nil {
		return err
	}

	req.Header.Set("Signature-Input", *sigInput)
	req.Header.Set("Signature", *sig)
	for _, line := range splitLines(*headerArg) {
		name, value, ok := cutHeader(line)
		if !ok {
			return fmt.Errorf("malformed header %q; expected 'Name: value'", line)
		}
		req.Header.Set(name, value)
	}
	req.Host = req.URL.Host

	canon, err := canonicalhttp.FromHTTPRequest(req, body)
	if err != nil {
		return err
	}

	result, err := httpmsig.Verify(httpmsig.VerifyInput{
		Request:              canon,
		SignatureInputHeader: *sigInput,
		SignatureHeader:      *sig,
		PublicKey:            pub,
	})
	if err != nil {
		fmt.Printf("FAIL: %v\n\n# Signature base the verifier built\n", err)
		return err
	}

	fmt.Printf("OK\n\n  key id     : %s\n  nonce      : %s\n  created    : %s\n  components : %d\n",
		result.KeyID, result.Nonce, result.Created.Format("2006-01-02T15:04:05Z07:00"), len(result.Components))
	fmt.Printf("\n# Signature base (%d bytes)\n%s\n", len(result.SignatureBase), result.SignatureBase)
	return nil
}
