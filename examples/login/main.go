// Command login signs in with the credential created by examples/register
// and verifies the assertion the way a WebAuthn server would.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/yashikota/bio"
	"github.com/yashikota/bio/internal/webauthntest"
)

type saved struct {
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"`
}

func main() {
	rp := webauthntest.Default

	file := filepath.Join(os.TempDir(), "bio_credential.json")
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("read %s: %v\nRun `go run ./examples/register` first.", file, err)
	}
	var s saved
	if err := json.Unmarshal(b, &s); err != nil {
		log.Fatalf("parse %s: %v", file, err)
	}

	authn, err := bio.New()
	if err != nil {
		log.Fatalf("bio.New: %v", err)
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	a, err := authn.GetAssertion(ctx, bio.GetAssertionOptions{
		RPID:             rp.ID,
		Challenge:        challenge,
		ClientDataJSON:   rp.ClientData("webauthn.get", challenge),
		AllowCredentials: []bio.CredentialDescriptor{{Type: "public-key", ID: s.CredentialID}},
		UserVerification: bio.UVRequired,
	})
	if err != nil {
		cancel()
		log.Fatalf("GetAssertion: %v", err)
	}
	cancel()

	count, err := rp.VerifyAssertion(challenge, a.CredentialID, a.AuthenticatorData, a.Signature, a.UserHandle, a.ClientDataJSON, s.PublicKey)
	if err != nil {
		log.Fatalf("relying party REJECTED the assertion: %v", err)
	}
	fmt.Println("Assertion verified by the relying party: OK")
	fmt.Printf("Sign count: %d, user handle: %x\n", count, a.UserHandle)
}
