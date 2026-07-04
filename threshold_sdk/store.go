package thresholdsdk

import (
	"errors"
)

// ErrNotFound is returned by a Store when a key is absent.
var ErrNotFound = errors.New("thresholdsdk: not found")

// Store persists ceremony outputs — the public RecoveryData blob, keyed by the
// group verifying key (the 33-byte compressed threshold public key the ceremony
// produced). One entry per produced key; a key-refresh updates the same entry,
// and the same participant set can hold several distinct keys. No secret material
// is stored: a participant's share is recovered on demand from the blob plus its
// host key.
//
// Backend-agnostic: a BadgerDB implementation lives in the badgerstore subpackage;
// embedders may supply their own without linking BadgerDB.
type Store interface {
	PutRecovery(groupKey, recovery []byte) error
	GetRecovery(groupKey []byte) ([]byte, error)
	Has(groupKey []byte) (bool, error)
	List() ([][]byte, error) // the group keys currently stored
	// Leader-only persistence.
	PutLeaderSecret(label string, a0 []byte) error
	GetLeaderSecret(label string) ([]byte, error)
	Close() error
}
