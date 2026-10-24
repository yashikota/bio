// Command register creates a credential and checks it the way a WebAuthn
// server would. Run examples/login afterwards to sign in with it.
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

// saved is what a server would store after registration.
type saved struct {
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"` // COSE
}

func main() {
	rp := webauthntest.Default // RP ID example.com, origin https://example.com

	authn, err := bio.New()
	if err != nil {
		log.Fatalf("bio.New: %v", err)
	}

	// In production the challenge comes from the server and the client data from the client.
	challenge := make([]byte, 32)
	userID := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		log.Fatal(err)
	}
	if _, err := rand.Read(userID); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	cred, err := authn.MakeCredential(ctx, bio.MakeCredentialOptions{
		RP:               bio.RelyingParty{ID: rp.ID, Name: "Example Corp"},
		User:             bio.User{ID: userID, Name: "user@example.com", DisplayName: "Example User"},
		Challenge:        challenge,
		ClientDataJSON:   rp.ClientData("webauthn.create", challenge),
		PubKeyCredParams: []bio.CredentialParameter{{Type: "public-key", Algorithm: bio.AlgES256}},
		UserVerification: bio.UVRequired,
	})
	if err != nil {
		cancel()
		log.Fatalf("MakeCredential: %v", err)
	}
	cancel()

	// Verify the registration exactly as a relying party would.
	pub, err := rp.VerifyRegistration(challenge, cred.ID, cred.AttestationObject, cred.ClientDataJSON)
	if err != nil {
		log.Fatalf("relying party REJECTED the registration: %v", err)
	}
	fmt.Println("Registration verified by the relying party: OK")
	fmt.Printf("Credential ID: %x\n", cred.ID)

	b, _ := json.Marshal(saved{CredentialID: cred.ID, PublicKey: pub})
	file := filepath.Join(os.TempDir(), "bio_credential.json")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		log.Fatalf("save credential: %v", err)
	}
	fmt.Printf("Saved to %s. Run `go run ./examples/login` to sign in.\n", file)
}
