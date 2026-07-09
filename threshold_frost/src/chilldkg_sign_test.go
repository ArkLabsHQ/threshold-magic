package threshold_signing

import (
	"crypto/rand"
	"testing"

	thres "github.com/ArkLabsHQ/threshold-magic/threshold_core"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// runChillDKG runs a full in-process ChillDKG (encrypted PedPop + CertEq) session
// and returns the resulting key packages, mirroring runDealerDKG but exercising
// the additive-pad encryption + certificate path.
func runChillDKG(t *testing.T, min, max uint16) ([]thres.KeyPackage, thres.PublicKeyPackage) {
	t.Helper()

	type party struct {
		id     thres.Identifier
		hostSk *secp256k1.PrivateKey
		secret thres.SecretKey
		coeffs []secp256k1.ModNScalar
		r1s    thres.Round1SecretPackage
		eph    thres.EphemeralKey
	}

	parties := make([]party, 0, max)
	hostPubs := make(map[thres.Identifier]*secp256k1.PublicKey, max)

	for i := uint16(1); i <= max; i++ {
		id, err := thres.IdentifierFromUint16(i)
		if err != nil {
			t.Fatalf("IdentifierFromUint16: %v", err)
		}
		hostSk, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("GeneratePrivateKey: %v", err)
		}
		coeffs, err := thres.GenerateCoefficients(min)
		if err != nil {
			t.Fatalf("GenerateCoefficients: %v", err)
		}
		parties = append(parties, party{id: id, hostSk: hostSk, secret: thres.SecretKey{Scalar: randomScalar(t)}, coeffs: coeffs})
		hostPubs[id] = hostSk.PubKey()
	}

	params, err := thres.NewSessionParams(min, hostPubs)
	if err != nil {
		t.Fatalf("NewSessionParams: %v", err)
	}

	// Round 1.
	round1 := make(map[thres.Identifier]thres.Round1Package, max)
	ephPubs := make(map[thres.Identifier]*secp256k1.PublicKey, max)
	for i := range parties {
		r1s, r1p, eph, err := thres.ParticipantStep1(params, parties[i].id, parties[i].secret, parties[i].coeffs, rand.Reader)
		if err != nil {
			t.Fatalf("ParticipantStep1: %v", err)
		}
		parties[i].r1s = r1s
		parties[i].eph = eph
		round1[parties[i].id] = r1p
		ephPubs[parties[i].id] = eph.Pub
	}
	if err := thres.CoordinatorStep1(params, round1); err != nil {
		t.Fatalf("CoordinatorStep1: %v", err)
	}

	// Round 2.
	perSender := make(map[thres.Identifier]thres.EncRound2, max)
	for i := range parties {
		peers := make(map[thres.Identifier]thres.Round1Package, max-1)
		for id, pkg := range round1 {
			if !id.Equal(parties[i].id) {
				peers[id] = pkg
			}
		}
		_, enc, err := thres.ParticipantStep2(params, parties[i].r1s, peers, parties[i].eph, parties[i].hostSk)
		if err != nil {
			t.Fatalf("ParticipantStep2: %v", err)
		}
		perSender[parties[i].id] = enc
	}

	encShare, err := thres.CoordinatorFinalize(perSender, params.IDs())
	if err != nil {
		t.Fatalf("CoordinatorFinalize: %v", err)
	}

	// Finalize.
	keyPackages := make([]thres.KeyPackage, 0, max)
	var pkp thres.PublicKeyPackage
	for i := range parties {
		out, _, _, err := thres.ParticipantFinalize(params, parties[i].id, encShare[parties[i].id], round1, ephPubs, parties[i].hostSk)
		if err != nil {
			t.Fatalf("ParticipantFinalize: %v", err)
		}
		keyPackages = append(keyPackages, out.Key)
		if len(pkp.VerifyingShares) == 0 {
			pkp = out.Public
		}
	}
	return keyPackages, pkp
}

// TestChillDKGSignAndAggregate proves shares produced by ChillDKG sign and
// aggregate into a valid Schnorr signature under the group key.
func TestChillDKGSignAndAggregate(t *testing.T) {
	minSigners := uint16(2)
	maxSigners := uint16(3)

	keys, pkp := runChillDKG(t, minSigners, maxSigners)

	signingPackage := SigningPackage{
		Commitments: make(map[thres.Identifier]SigningCommitments, minSigners),
		Message:     []byte("chilldkg + frost end-to-end signature"),
	}

	nonces := make(map[thres.Identifier]SigningNonce, minSigners)
	signatureShares := make(map[thres.Identifier]SignatureShare, minSigners)

	for i := 0; i < int(minSigners); i++ {
		kp := keys[i]
		nonce := NewNonce(kp.SecretShare, rand.Reader)
		nonces[kp.Identifier] = nonce
		signingPackage.Commitments[kp.Identifier] = nonce.commitments
	}

	for i := 0; i < int(minSigners); i++ {
		kp := keys[i]
		share, err := Sign(signingPackage, nonces[kp.Identifier], kp)
		if err != nil {
			t.Fatalf("Sign(%v): %v", kp.Identifier, err)
		}
		signatureShares[kp.Identifier] = *share
	}

	signature, err := Aggregate(&signingPackage, signatureShares, pkp)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	challenge, err := ComputeChallenge(&signature.R, pkp.VerifyingKey, signingPackage.Message)
	if err != nil {
		t.Fatalf("ComputeChallenge: %v", err)
	}

	left := secp256k1.JacobianPoint{}
	secp256k1.ScalarBaseMultNonConst(&signature.Z, &left)

	eY := secp256k1.JacobianPoint{}
	secp256k1.ScalarMultNonConst(challenge, &pkp.VerifyingKey.E, &eY)

	right := secp256k1.JacobianPoint{}
	secp256k1.AddNonConst(&signature.R, &eY, &right)

	if !left.EquivalentNonConst(&right) {
		t.Fatal("aggregated signature did not verify against group key")
	}
}
