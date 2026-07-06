package main

import (
	"context"
	"fmt"
	"log"

	"github.com/yashikota/bio"
)

func main() {
	authn, err := bio.New()
	if err != nil {
		log.Fatalf("bio.New: %v", err)
	}

	info, err := authn.Available(context.Background())
	if err != nil {
		log.Fatalf("Available: %v", err)
	}

	fmt.Printf("Biometric available : %v\n", info.Available)
	fmt.Printf("Type                : %v\n", info.BiometryType)
	fmt.Printf("Enrolled            : %v\n", info.Enrolled)
}
