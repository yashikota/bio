package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/yashikota/bio"
)

func buildClientDataJSON(typ, origin string, challenge []byte) ([]byte, error) {
	return json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{
		Type:      typ,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    origin,
	})
}

func main() {
	authn, err := bio.New()
	if err != nil {
		log.Fatalf("bio.New: %v", err)
	}

	// Generate a random challenge (in production, this comes from the server).
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		log.Fatalf("rand: %v", err)
	}

	// Generate a random user ID.
	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		log.Fatalf("rand: %v", err)
	}

	// Build clientDataJSON (in production, the browser/client constructs this).
	clientDataJSON, err := buildClientDataJSON("webauthn.create", "https://example.com", challenge)
	if err != nil {
		log.Fatalf("clientDataJSON: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cred, err := authn.MakeCredential(ctx, bio.MakeCredentialOptions{
		RP: bio.RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
		},
		User: bio.User{
			ID:          userID,
			Name:        "user@example.com",
			DisplayName: "Example User",
		},
		Challenge:      challenge,
		ClientDataJSON: clientDataJSON,
		PubKeyCredParams: []bio.CredentialParameter{
			{Type: "public-key", Algorithm: bio.AlgES256},
		},
		Attestation:      bio.AttestationNone,
		UserVerification: bio.UVRequired,
	})
	if err != nil {
		log.Fatalf("MakeCredential: %v", err)
	}

	credIDBase64 := base64.RawURLEncoding.EncodeToString(cred.ID)

	fmt.Printf("Credential ID  : %s\n", credIDBase64)
	fmt.Printf("Attest. Object : %d bytes\n", len(cred.AttestationObject))
	fmt.Printf("Auth Data      : %d bytes\n", len(cred.AuthenticatorData))
	fmt.Printf("Transport      : %v\n", cred.Transport)

	// Save credential ID to a temp file for use by the login example.
	credFile := filepath.Join(os.TempDir(), "bio_cred_id.txt")
	if err := os.WriteFile(credFile, []byte(credIDBase64), 0600); err != nil {
		log.Printf("Warning: could not save credential ID: %v", err)
	} else {
		fmt.Printf("\nCredential ID saved to %s\n", credFile)
		fmt.Println("Run `go run ./examples/login` to authenticate.")
	}
}
