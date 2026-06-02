package thresholdsdk

import (
	"errors"

	badger "github.com/dgraph-io/badger/v4"
)

// ErrNotFound is returned by a Store when a key is absent.
var ErrNotFound = errors.New("thresholdsdk: not found")

// Store persists ceremony outputs — the public RecoveryData blob, keyed by the
// session id (SessionParams.SessionID, i.e. the deterministic params_id). No
// secret material is stored: a participant's share is recovered on demand from
// the blob plus its host key.
type Store interface {
	PutRecovery(sessionID, blob []byte) error
	GetRecovery(sessionID []byte) ([]byte, error)
	Has(sessionID []byte) (bool, error)
	Close() error
}

const recoveryPrefix = "recovery/"

func recoveryKey(sessionID []byte) []byte { return append([]byte(recoveryPrefix), sessionID...) }

// badgerStore is a BadgerDB-backed Store.
type badgerStore struct {
	db *badger.DB
}

// OpenBadgerStore opens a BadgerDB-backed Store at path. An empty path opens an
// in-memory database (nothing is written to disk), convenient for tests and
// ephemeral use.
func OpenBadgerStore(path string) (Store, error) {
	opts := badger.DefaultOptions(path).WithLogger(nil)
	if path == "" {
		opts = opts.WithInMemory(true)
	}
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &badgerStore{db: db}, nil
}

func (s *badgerStore) put(key, val []byte) error {
	return s.db.Update(func(txn *badger.Txn) error { return txn.Set(key, val) })
}

func (s *badgerStore) get(key []byte) ([]byte, error) {
	var out []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, gerr := txn.Get(key)
		if gerr != nil {
			return gerr
		}
		out, gerr = item.ValueCopy(nil)
		return gerr
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *badgerStore) PutRecovery(sessionID, blob []byte) error {
	return s.put(recoveryKey(sessionID), blob)
}
func (s *badgerStore) GetRecovery(sessionID []byte) ([]byte, error) {
	return s.get(recoveryKey(sessionID))
}

func (s *badgerStore) Has(sessionID []byte) (bool, error) {
	_, err := s.GetRecovery(sessionID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *badgerStore) Close() error { return s.db.Close() }
