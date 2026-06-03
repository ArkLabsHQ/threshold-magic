// Package thresholdsdkintegration holds the Docker-based integration test for
// the thresholdsdk SDK and the small env-driven harness it runs in containers.
package thresholdsdkintegration

import (
	"encoding/hex"
	"encoding/json"

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SessionDescriptor is the agreed participant set, passed verbatim to every node
// (coordinator and participants) so each derives identical SessionParams.
type SessionDescriptor struct {
	Threshold    uint16                  `json:"threshold"`
	Participants []ParticipantDescriptor `json:"participants"`
}

// ParticipantDescriptor is one participant's agreed identifier and host pubkey.
type ParticipantDescriptor struct {
	ID         string `json:"id"`         // hex of Identifier.Serialize() (32-byte big-endian)
	HostPubkey string `json:"hostPubkey"` // hex of compressed secp256k1 pubkey (33 bytes)
}

// Marshal encodes the descriptor as a JSON string.
func (d SessionDescriptor) Marshal() (string, error) {
	b, err := json.Marshal(d)
	return string(b), err
}

// ParseSessionDescriptor decodes the JSON form.
func ParseSessionDescriptor(s string) (SessionDescriptor, error) {
	var d SessionDescriptor
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		return SessionDescriptor{}, err
	}
	return d, nil
}

// Params builds SessionParams from the descriptor. NewSessionParams recomputes and
// validates the deterministic SessionID, so an identical descriptor yields
// identical params on every node.
func (d SessionDescriptor) Params() (core.SessionParams, error) {
	hostPubs := make(map[core.Identifier]*secp.PublicKey, len(d.Participants))
	for _, p := range d.Participants {
		idb, err := hex.DecodeString(p.ID)
		if err != nil {
			return core.SessionParams{}, err
		}
		id, err := core.DeserializeIdentifier(idb)
		if err != nil {
			return core.SessionParams{}, err
		}
		pkb, err := hex.DecodeString(p.HostPubkey)
		if err != nil {
			return core.SessionParams{}, err
		}
		pub, err := secp.ParsePubKey(pkb)
		if err != nil {
			return core.SessionParams{}, err
		}
		hostPubs[id] = pub
	}
	return core.NewSessionParams(d.Threshold, hostPubs)
}
