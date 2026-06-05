package thresholdsdk

import (
	"errors"

	badger "github.com/dgraph-io/badger/v4"
)

// ErrNotFound is returned by a Store when a key is absent.
var ErrNotFound = errors.New("thresholdsdk: not found")

// Store persists ceremony outputs — the public RecoveryData blob, keyed by the
// group verifying key (the 33-byte compressed threshold public key the ceremony
// produced). One entry per produced key; a key-refresh updates the same entry,
// and the same participant set can hold several distinct keys. No secret material
// is stored: a participant's share is recovered on demand from the blob plus its
// host key.
type Store interface {
	PutRecovery(groupKey, blob []byte) error
	GetRecovery(groupKey []byte) ([]byte, error)
	Has(groupKey []byte) (bool, error)
	List() ([][]byte, error) // the group keys currently stored
	// Leader-only persistence (leader/follower sessions). The leader generates its
	// group secret a0 once and reuses it across re-DKGs, so the group public key is
	// stable as members join or are banned. GetLeaderSecret returns ErrNotFound
	// before the first PutLeaderSecret.
	PutLeaderSecret(a0 []byte) error
	GetLeaderSecret() ([]byte, error)
	Close() error
}

const (
	recoveryPrefix  = "recovery/"
	leaderSecretKey = "leader/secret"
)

func recoveryKey(groupKey []byte) []byte { return append([]byte(recoveryPrefix), groupKey...) }

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

func (s *badgerStore) PutRecovery(groupKey, blob []byte) error {
	return s.put(recoveryKey(groupKey), blob)
}
func (s *badgerStore) GetRecovery(groupKey []byte) ([]byte, error) {
	return s.get(recoveryKey(groupKey))
}

func (s *badgerStore) PutLeaderSecret(a0 []byte) error { return s.put([]byte(leaderSecretKey), a0) }
func (s *badgerStore) GetLeaderSecret() ([]byte, error) { return s.get([]byte(leaderSecretKey)) }

func (s *badgerStore) Has(groupKey []byte) (bool, error) {
	_, err := s.GetRecovery(groupKey)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// List returns the group keys currently stored (prefix scan; values not loaded).
func (s *badgerStore) List() ([][]byte, error) {
	prefix := []byte(recoveryPrefix)
	var keys [][]byte
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			k := it.Item().KeyCopy(nil)
			keys = append(keys, k[len(prefix):])
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *badgerStore) Close() error { return s.db.Close() }
