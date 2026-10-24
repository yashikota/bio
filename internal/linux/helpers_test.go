//go:build linux

package linux_test

import (
	"crypto/elliptic"

	"github.com/google/go-tpm/tpm2/transport"
)

type transportTPM = transport.TPMCloser

func ellipticP256() elliptic.Curve { return elliptic.P256() }
