package thresholdsdk

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Leader commands are pushed to followers over the (untrusted) relay, so they are
// authenticated end-to-end: each is signed by the leader's HOST key over a tagged
// hash of its canonical JSON, and carries a monotonic epoch (anti-replay). A follower
// verifies against the leader host key it pinned at join time before acting.

const tagLeaderCmd = "thresholdmagic/leader_cmd"
const tagJoin = "thresholdmagic/join"

// signJoinProof proves possession of the joining host key: a BIP340 signature by it
// over tagged_hash("…/join", hostpubkey). The leader verifies it before admitting
// the key, so a party cannot register a host key it does not control.
func signJoinProof(hostSk *secp.PrivateKey) ([]byte, error) {
	d := *chainhash.TaggedHash([]byte(tagJoin), hostSk.PubKey().SerializeCompressed())
	priv, _ := btcec.PrivKeyFromBytes(hostSk.Serialize())
	sig, err := schnorr.Sign(priv, d[:])
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func verifyJoinProof(pub *secp.PublicKey, proof []byte) bool {
	d := *chainhash.TaggedHash([]byte(tagJoin), pub.SerializeCompressed())
	sig, err := schnorr.ParseSignature(proof)
	if err != nil {
		return false
	}
	bpub, err := btcec.ParsePubKey(pub.SerializeCompressed())
	if err != nil {
		return false
	}
	return sig.Verify(d[:], bpub)
}

const (
	cmdRekey   = "rekey"   // (re-)run the DKG over Members at Threshold
	cmdRemoved = "removed" // Target has been evicted; it must stop
)

// leaderCmd is the body of a signed leader instruction (canonical JSON; Go sorts map
// keys, so the encoding is deterministic).
type leaderCmd struct {
	Kind      string            `json:"kind"`
	Epoch     uint64            `json:"epoch"`
	Threshold uint16            `json:"t,omitempty"`
	Leader    string            `json:"leader,omitempty"`  // hex(identifier)
	Members   map[string]string `json:"members,omitempty"` // hex(id) -> hex(hostpub)
	Target    string            `json:"target,omitempty"`  // hex(id), for cmdRemoved
	Label     string            `json:"label,omitempty"`   // secret label this rekey (re-)shares
}

// signedCmd is the wire payload: the command plus the leader's signature over its
// tagged-hash digest.
type signedCmd struct {
	Cmd leaderCmd `json:"cmd"`
	Sig string    `json:"sig"` // hex BIP340 signature
}

func (c leaderCmd) digest() (chainhash.Hash, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return chainhash.Hash{}, err
	}
	return *chainhash.TaggedHash([]byte(tagLeaderCmd), b), nil
}

// signCommand serializes and signs a command with the leader's host key.
func signCommand(hostSk *secp.PrivateKey, c leaderCmd) ([]byte, error) {
	d, err := c.digest()
	if err != nil {
		return nil, err
	}
	priv, _ := btcec.PrivKeyFromBytes(hostSk.Serialize())
	sig, err := schnorr.Sign(priv, d[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedCmd{Cmd: c, Sig: hex.EncodeToString(sig.Serialize())})
}

// verifyCommand parses a signed command and checks the signature against leaderPub.
func verifyCommand(payload []byte, leaderPub *secp.PublicKey) (leaderCmd, error) {
	var sc signedCmd
	if err := json.Unmarshal(payload, &sc); err != nil {
		return leaderCmd{}, err
	}
	d, err := sc.Cmd.digest()
	if err != nil {
		return leaderCmd{}, err
	}
	sb, err := hex.DecodeString(sc.Sig)
	if err != nil {
		return leaderCmd{}, err
	}
	sig, err := schnorr.ParseSignature(sb)
	if err != nil {
		return leaderCmd{}, err
	}
	pub, err := btcec.ParsePubKey(leaderPub.SerializeCompressed())
	if err != nil {
		return leaderCmd{}, err
	}
	if !sig.Verify(d[:], pub) {
		return leaderCmd{}, errors.New("thresholdsdk: bad leader command signature")
	}
	return sc.Cmd, nil
}

// rekeyCommand builds an unsigned rekey command for a committee, tagged with the
// label of the secret it (re-)shares.
func rekeyCommand(label string, epoch uint64, t uint16, leader core.Identifier, committee map[core.Identifier]*secp.PublicKey) leaderCmd {
	members := make(map[string]string, len(committee))
	for id, pub := range committee {
		members[addrOf(id)] = hex.EncodeToString(pub.SerializeCompressed())
	}
	return leaderCmd{Kind: cmdRekey, Epoch: epoch, Threshold: t, Leader: addrOf(leader), Members: members, Label: label}
}

// session reconstructs the SessionParams + leader identifier a rekey command
// describes, so every follower derives byte-identical params.
func (c leaderCmd) session() (core.SessionParams, core.Identifier, error) {
	committee := make(map[core.Identifier]*secp.PublicKey, len(c.Members))
	for idHex, pubHex := range c.Members {
		id, err := idOf(idHex)
		if err != nil {
			return core.SessionParams{}, core.Identifier{}, err
		}
		pb, err := hex.DecodeString(pubHex)
		if err != nil {
			return core.SessionParams{}, core.Identifier{}, err
		}
		pub, err := secp.ParsePubKey(pb)
		if err != nil {
			return core.SessionParams{}, core.Identifier{}, err
		}
		committee[id] = pub
	}
	params, err := core.NewSessionParams(c.Threshold, committee)
	if err != nil {
		return core.SessionParams{}, core.Identifier{}, err
	}
	leader, err := idOf(c.Leader)
	if err != nil {
		return core.SessionParams{}, core.Identifier{}, err
	}
	return params, leader, nil
}
