package thresholdchilldkg

import (
	"encoding/hex"
	"encoding/json"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// Wire (de)serialization between thresholdcore values and transport payloads.
// Addresses and map keys are hex strings so payloads survive any text transport.

func addrOf(id thres.Identifier) string { return hex.EncodeToString(id.Serialize()) }

func idOf(addr string) (thres.Identifier, error) {
	b, err := hex.DecodeString(addr)
	if err != nil {
		return thres.Identifier{}, err
	}
	return thres.DeserializeIdentifier(b)
}

func pubToHex(pub *secp.PublicKey) string { return hex.EncodeToString(pub.SerializeCompressed()) }

func hexToPub(s string) (*secp.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return secp.ParsePubKey(b)
}

func scalarToHex(s secp.ModNScalar) string {
	b := s.Bytes()
	return hex.EncodeToString(b[:])
}

func hexToScalar(s string) (secp.ModNScalar, error) {
	var out secp.ModNScalar
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	out.SetByteSlice(b)
	return out, nil
}

// --- round1 (participant -> coordinator) ---

type round1Wire struct {
	Round1 json.RawMessage `json:"round1"`
	EphPub string          `json:"ephPub"`
}

func marshalRound1(pkg thres.Round1Package, ephPub *secp.PublicKey) ([]byte, error) {
	raw, err := json.Marshal(pkg)
	if err != nil {
		return nil, err
	}
	return json.Marshal(round1Wire{Round1: raw, EphPub: pubToHex(ephPub)})
}

func unmarshalRound1(payload []byte) (thres.Round1Package, *secp.PublicKey, error) {
	var w round1Wire
	if err := json.Unmarshal(payload, &w); err != nil {
		return thres.Round1Package{}, nil, err
	}
	var pkg thres.Round1Package
	if err := json.Unmarshal(w.Round1, &pkg); err != nil {
		return thres.Round1Package{}, nil, err
	}
	pub, err := hexToPub(w.EphPub)
	if err != nil {
		return thres.Round1Package{}, nil, err
	}
	return pkg, pub, nil
}

// --- cmsg1 (coordinator -> all) ---

type cmsg1Wire struct {
	Round1  map[string]json.RawMessage `json:"round1"`
	EphPubs map[string]string          `json:"ephPubs"`
}

func marshalCmsg1(round1 map[thres.Identifier]thres.Round1Package, ephPubs map[thres.Identifier]*secp.PublicKey) ([]byte, error) {
	w := cmsg1Wire{
		Round1:  make(map[string]json.RawMessage, len(round1)),
		EphPubs: make(map[string]string, len(ephPubs)),
	}
	for id, pkg := range round1 {
		raw, err := json.Marshal(pkg)
		if err != nil {
			return nil, err
		}
		w.Round1[addrOf(id)] = raw
	}
	for id, pub := range ephPubs {
		w.EphPubs[addrOf(id)] = pubToHex(pub)
	}
	return json.Marshal(w)
}

func unmarshalCmsg1(payload []byte) (map[thres.Identifier]thres.Round1Package, map[thres.Identifier]*secp.PublicKey, error) {
	var w cmsg1Wire
	if err := json.Unmarshal(payload, &w); err != nil {
		return nil, nil, err
	}
	round1 := make(map[thres.Identifier]thres.Round1Package, len(w.Round1))
	for addr, raw := range w.Round1 {
		id, err := idOf(addr)
		if err != nil {
			return nil, nil, err
		}
		var pkg thres.Round1Package
		if err := json.Unmarshal(raw, &pkg); err != nil {
			return nil, nil, err
		}
		round1[id] = pkg
	}
	ephPubs := make(map[thres.Identifier]*secp.PublicKey, len(w.EphPubs))
	for addr, s := range w.EphPubs {
		id, err := idOf(addr)
		if err != nil {
			return nil, nil, err
		}
		pub, err := hexToPub(s)
		if err != nil {
			return nil, nil, err
		}
		ephPubs[id] = pub
	}
	return round1, ephPubs, nil
}

// --- enc2 (participant -> coordinator) ---

func marshalEnc2(enc thres.EncRound2) ([]byte, error) {
	m := make(map[string]string, len(enc.Ciphertexts))
	for id, c := range enc.Ciphertexts {
		m[addrOf(id)] = scalarToHex(c)
	}
	return json.Marshal(m)
}

func unmarshalEnc2(payload []byte) (thres.EncRound2, error) {
	var m map[string]string
	if err := json.Unmarshal(payload, &m); err != nil {
		return thres.EncRound2{}, err
	}
	out := thres.EncRound2{Ciphertexts: make(map[thres.Identifier]secp.ModNScalar, len(m))}
	for addr, s := range m {
		id, err := idOf(addr)
		if err != nil {
			return thres.EncRound2{}, err
		}
		c, err := hexToScalar(s)
		if err != nil {
			return thres.EncRound2{}, err
		}
		out.Ciphertexts[id] = c
	}
	return out, nil
}

// --- certset (coordinator -> all) ---

func marshalCertSet(sigs map[thres.Identifier]*schnorr.Signature) ([]byte, error) {
	m := make(map[string]string, len(sigs))
	for id, sig := range sigs {
		m[addrOf(id)] = hex.EncodeToString(sig.Serialize())
	}
	return json.Marshal(m)
}

func unmarshalCertSet(payload []byte) (map[thres.Identifier]*schnorr.Signature, error) {
	var m map[string]string
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	out := make(map[thres.Identifier]*schnorr.Signature, len(m))
	for addr, s := range m {
		id, err := idOf(addr)
		if err != nil {
			return nil, err
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		sig, err := schnorr.ParseSignature(b)
		if err != nil {
			return nil, err
		}
		out[id] = sig
	}
	return out, nil
}
