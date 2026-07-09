package thresholdcore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Share recovery from a RecoveryData blob, plus its canonical serialization.

// ErrHostKeyMismatch is returned when the host key matches no participant in the
// recovery data.
var ErrHostKeyMismatch = errors.New("host key does not match recovery data")

// Verify checks the recovery data is internally consistent and carries a valid
// N-of-N success certificate over its own transcript. It must pass before any
// data recovered from the blob is trusted.
func (rd RecoveryData) Verify() error {
	if err := rd.Params.Validate(); err != nil {
		return err
	}
	group, pkp, err := groupCommitment(rd.Params, rd.Round1)
	if err != nil {
		return err
	}
	eqInput, _, err := BuildEqInput(rd.Params, rd.Round1, rd.EphPubs, group, pkp.VerifyingKey)
	if err != nil {
		return err
	}
	return CertEqVerifyAll(eqInput, rd.Certificate, rd.Params.HostPubs, int(rd.Params.N))
}

// identify returns the participant whose host public key is hostPub. Host keys
// are unique (enforced by SessionParams.Validate), so the match is unambiguous —
// a participant's identifier is recoverable from its host key alone.
func (rd RecoveryData) identify(hostPub *secp.PublicKey) (Identifier, error) {
	want := hostPub.SerializeCompressed()
	for id, pub := range rd.Params.HostPubs {
		if pub != nil && bytes.Equal(pub.SerializeCompressed(), want) {
			return id, nil
		}
	}
	return Identifier{}, ErrHostKeyMismatch
}

// RecoverShare reconstructs the caller's DKG output from the recovery data using
// only its host secret key (the identifier is found by host-pubkey lookup). It
// verifies the certificate first; DecryptAndVerifyShare re-checks the share
// against the certified group commitment, so a tampered share errors rather than
// recovering a wrong one.
func RecoverShare(rd RecoveryData, hostSk *secp.PrivateKey) (DKGOutput, error) {
	if hostSk == nil {
		return DKGOutput{}, ErrHostKeyMismatch
	}
	if err := rd.Verify(); err != nil {
		return DKGOutput{}, err
	}
	self, err := rd.identify(hostSk.PubKey())
	if err != nil {
		return DKGOutput{}, err
	}

	group, pkp, err := groupCommitment(rd.Params, rd.Round1)
	if err != nil {
		return DKGOutput{}, err
	}
	enc, ok := rd.EncShares[self]
	if !ok {
		return DKGOutput{}, ErrIncorrectPackage
	}
	share, err := DecryptAndVerifyShare(self, enc, rd.Params, rd.EphPubs, hostSk, group)
	if err != nil {
		return DKGOutput{}, err
	}

	scalar := (secp.ModNScalar)(share)
	kp := KeyPackage{
		Identifier:     self,
		SecretShare:    share,
		VerifyingShare: elemBaseMul(&scalar),
		VerifyingKey:   pkp.VerifyingKey,
		MinSigners:     rd.Params.T,
	}
	return DKGOutput{Key: kp, Public: pkp}, nil
}

// GroupVerifyingKey returns the group verifying key (the threshold public key)
// derived from the recovery data's round-1 commitments. It is public information
// and needs no secret, so a coordinator can compute it to index stored recovery
// data by the key it produced.
func (rd RecoveryData) GroupVerifyingKey() (VerifyingKey, error) {
	_, pkp, err := groupCommitment(rd.Params, rd.Round1)
	if err != nil {
		return VerifyingKey{}, err
	}
	return pkp.VerifyingKey, nil
}

// recoveryWire is the canonical wire form of RecoveryData: hex strings and
// Round1Package's own JSON only — never a raw secp type (whose unexported fields
// marshal to {}). Hex-identifier map keys make Go's JSON output deterministic.
// SessionID is omitted and re-derived (ParamsID) on parse.
type recoveryWire struct {
	T         uint16                     `json:"t"`
	HostPubs  map[string]string          `json:"hostPubs"`
	Round1    map[string]json.RawMessage `json:"round1"`
	EphPubs   map[string]string          `json:"ephPubs"`
	EncShares map[string]string          `json:"encShares"`
	Cert      map[string]string          `json:"cert"`
}

func hexID(id Identifier) string { return hex.EncodeToString(id.Serialize()) }

func idFromHex(h string) (Identifier, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return Identifier{}, err
	}
	return DeserializeIdentifier(b)
}

func pubFromHex(h string) (*secp.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return secp.ParsePubKey(b)
}

// Serialize encodes the recovery data into its canonical, deterministic form.
func (rd RecoveryData) Serialize() ([]byte, error) {
	w := recoveryWire{
		T:         rd.Params.T,
		HostPubs:  make(map[string]string, len(rd.Params.HostPubs)),
		Round1:    make(map[string]json.RawMessage, len(rd.Round1)),
		EphPubs:   make(map[string]string, len(rd.EphPubs)),
		EncShares: make(map[string]string, len(rd.EncShares)),
		Cert:      make(map[string]string, len(rd.Certificate)),
	}
	for id, pub := range rd.Params.HostPubs {
		if pub == nil {
			return nil, ErrMissingHostKey
		}
		w.HostPubs[hexID(id)] = hex.EncodeToString(pub.SerializeCompressed())
	}
	for id, r1 := range rd.Round1 {
		raw, err := json.Marshal(r1)
		if err != nil {
			return nil, err
		}
		w.Round1[hexID(id)] = raw
	}
	for id, pub := range rd.EphPubs {
		if pub == nil {
			return nil, ErrMissingEphKey
		}
		w.EphPubs[hexID(id)] = hex.EncodeToString(pub.SerializeCompressed())
	}
	for id, s := range rd.EncShares {
		b := s.Bytes()
		w.EncShares[hexID(id)] = hex.EncodeToString(b[:])
	}
	for id, sig := range rd.Certificate {
		if sig == nil {
			return nil, ErrInvalidCertSignature
		}
		w.Cert[hexID(id)] = hex.EncodeToString(sig.Serialize())
	}
	return json.Marshal(w)
}

// ParseRecoveryData decodes the canonical form. It rebuilds SessionParams via
// NewSessionParams, which re-derives and validates the SessionID — the blob's
// session id is never trusted.
func ParseRecoveryData(b []byte) (RecoveryData, error) {
	var w recoveryWire
	if err := json.Unmarshal(b, &w); err != nil {
		return RecoveryData{}, err
	}

	hostPubs := make(map[Identifier]*secp.PublicKey, len(w.HostPubs))
	for h, ph := range w.HostPubs {
		id, err := idFromHex(h)
		if err != nil {
			return RecoveryData{}, err
		}
		pub, err := pubFromHex(ph)
		if err != nil {
			return RecoveryData{}, err
		}
		hostPubs[id] = pub
	}
	params, err := NewSessionParams(w.T, hostPubs)
	if err != nil {
		return RecoveryData{}, err
	}

	round1 := make(map[Identifier]Round1Package, len(w.Round1))
	for h, raw := range w.Round1 {
		id, err := idFromHex(h)
		if err != nil {
			return RecoveryData{}, err
		}
		var r1 Round1Package
		if err := json.Unmarshal(raw, &r1); err != nil {
			return RecoveryData{}, err
		}
		round1[id] = r1
	}

	ephPubs := make(map[Identifier]*secp.PublicKey, len(w.EphPubs))
	for h, ph := range w.EphPubs {
		id, err := idFromHex(h)
		if err != nil {
			return RecoveryData{}, err
		}
		pub, err := pubFromHex(ph)
		if err != nil {
			return RecoveryData{}, err
		}
		ephPubs[id] = pub
	}

	encShares := make(map[Identifier]secp.ModNScalar, len(w.EncShares))
	for h, sh := range w.EncShares {
		id, err := idFromHex(h)
		if err != nil {
			return RecoveryData{}, err
		}
		sb, err := hex.DecodeString(sh)
		if err != nil {
			return RecoveryData{}, err
		}
		var s secp.ModNScalar
		s.SetByteSlice(sb)
		encShares[id] = s
	}

	cert := make(map[Identifier]*schnorr.Signature, len(w.Cert))
	for h, sgh := range w.Cert {
		id, err := idFromHex(h)
		if err != nil {
			return RecoveryData{}, err
		}
		sb, err := hex.DecodeString(sgh)
		if err != nil {
			return RecoveryData{}, err
		}
		sig, err := schnorr.ParseSignature(sb)
		if err != nil {
			return RecoveryData{}, err
		}
		cert[id] = sig
	}

	return RecoveryData{
		Params:      params,
		Round1:      round1,
		EphPubs:     ephPubs,
		EncShares:   encShares,
		Certificate: cert,
	}, nil
}
