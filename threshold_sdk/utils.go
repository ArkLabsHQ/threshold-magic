package thresholdsdk

import (
	"encoding/hex"
	"errors"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func addrOf(id thres.Identifier) string { return hex.EncodeToString(id.Serialize()) }

func idOf(addr string) (thres.Identifier, error) {
	b, err := hex.DecodeString(addr)
	if err != nil {
		return thres.Identifier{}, err
	}
	return thres.DeserializeIdentifier(b)
}

// HostKeyFromHex parses a hex-encoded 32-byte secp256k1 host secret, rejecting an
// out-of-range length and the zero key. It is a convenience for callers (leaders and
// followers) holding the secret as a string; the SDK itself takes a *secp.PrivateKey.
func HostKeyFromHex(s string) (*secp.PrivateKey, error) {
	const hostSecretLen = 32
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != hostSecretLen {
		return nil, errors.New("thresholdsdk: host secret must be 32 bytes")
	}
	sk := secp.PrivKeyFromBytes(b)
	if sk.Key.IsZero() {
		return nil, errors.New("thresholdsdk: host secret is zero")
	}
	return sk, nil
}
