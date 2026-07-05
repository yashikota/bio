package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yashikota/bio"
)

func main() {
	authn, err := bio.New(bio.WithLocalizedReason("Register biometric credential"))
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
		Challenge: challenge,
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
	if err := os.WriteFile("/tmp/bio_cred_id.txt", []byte(credIDBase64), 0600); err != nil {
		log.Printf("Warning: could not save credential ID: %v", err)
	} else {
		fmt.Println("\nCredential ID saved to /tmp/bio_cred_id.txt")
		fmt.Println("Run `go run ./examples/login` to authenticate.")
	}
}
