package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yashikota/bio"
)

func main() {
	// Load the credential ID saved by the register example.
	raw, err := os.ReadFile("/tmp/bio_cred_id.txt")
	if err != nil {
		log.Fatalf("Could not read credential ID from /tmp/bio_cred_id.txt: %v\n"+
			"Run `go run ./examples/register` first.", err)
	}
	credID, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		log.Fatalf("Decode credential ID: %v", err)
	}

	authn, err := bio.New(bio.WithLocalizedReason("Log in with biometrics"))
	if err != nil {
		log.Fatalf("bio.New: %v", err)
	}

	// Generate a random challenge (in production, this comes from the server).
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		log.Fatalf("rand: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	assertion, err := authn.GetAssertion(ctx, bio.GetAssertionOptions{
		RPID:      "example.com",
		Challenge: challenge,
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
