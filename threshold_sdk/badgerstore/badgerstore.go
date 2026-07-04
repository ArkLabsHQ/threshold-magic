// Package badgerstore provides a BadgerDB-backed implementation of
// thresholdsdk.Store. It is a separate package so that importing thresholdsdk
// does not pull in BadgerDB; embedders that supply their own Store (e.g. one
// backed by encrypted object storage) link none of badger's dependencies.
package badgerstore

import (
	"errors"

	badger "github.com/dgraph-io/badger/v4"

	sdk "thresholdsdk"
)

const (
	recoveryPrefix  = "recovery/"
	leaderSecretKey = "leader/secret"
)

func recoveryKey(groupKey []byte) []byte { return append([]byte(recoveryPrefix), groupKey...) }

// badgerStore is a BadgerDB-backed Store.
type badgerStore struct {
	db *badger.DB
}

// Open opens a BadgerDB-backed Store at path. An empty path opens an in-memory
// database (nothing is written to disk), convenient for tests and ephemeral use.
func Open(path string) (sdk.Store, error) {
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
		return nil, sdk.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *badgerStore) PutRecovery(groupKey, recovery []byte) error {
	return s.put(recoveryKey(groupKey), recovery)
}
func (s *badgerStore) GetRecovery(groupKey []byte) ([]byte, error) {
	return s.get(recoveryKey(groupKey))
}

func (s *badgerStore) PutLeaderSecret(label string, a0 []byte) error {
	return s.put([]byte(leaderSecretKey+"/"+label), a0)
}
func (s *badgerStore) GetLeaderSecret(label string) ([]byte, error) {
	return s.get([]byte(leaderSecretKey + "/" + label))
}

func (s *badgerStore) Has(groupKey []byte) (bool, error) {
	_, err := s.GetRecovery(groupKey)
	if errors.Is(err, sdk.ErrNotFound) {
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
