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
	"strings"
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
	// Load the credential ID saved by the register example.
	credFile := filepath.Join(os.TempDir(), "bio_cred_id.txt")
	raw, err := os.ReadFile(credFile)
	if err != nil {
		log.Fatalf("Could not read credential ID from %s: %v\nRun `go run ./examples/register` first.", credFile, err)
	}
	credID, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		log.Fatalf("Decode credential ID: %v", err)
	}

	authn, err := bio.New()
	if err != nil {
		log.Fatalf("bio.New: %v", err)
	}

	// Generate a random challenge (in production, this comes from the server).
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		log.Fatalf("rand: %v", err)
	}

	// Build clientDataJSON (in production, the browser/client constructs this).
	clientDataJSON, err := buildClientDataJSON("webauthn.get", "https://example.com", challenge)
	if err != nil {
		log.Fatalf("clientDataJSON: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	assertion, err := authn.GetAssertion(ctx, bio.GetAssertionOptions{
		RPID:           "example.com",
		Challenge:      challenge,
		ClientDataJSON: clientDataJSON,
		AllowCredentials: []bio.CredentialDescriptor{
			{Type: "public-key", ID: credID},
		},
		UserVerification: bio.UVRequired,
	})
	if err != nil {
		log.Fatalf("GetAssertion: %v", err)
	}

	fmt.Printf("Credential ID  : %s\n", base64.RawURLEncoding.EncodeToString(assertion.CredentialID))
	fmt.Printf("Auth Data      : %d bytes\n", len(assertion.AuthenticatorData))
	fmt.Printf("Signature      : %d bytes\n", len(assertion.Signature))
	fmt.Println("\nAuthentication successful!")
	fmt.Println("Send AuthenticatorData + Signature + ClientDataJSON to your server for verification.")
}
