package thresholdsdk

import "sync"

// memStore is an in-memory Store for tests. It avoids depending on the
// badgerstore subpackage (which would form an import cycle, since badgerstore
// imports this package) and keeps the core package's tests badger-free.
type memStore struct {
	mu       sync.Mutex
	recovery map[string][]byte
	leader   map[string][]byte // label -> a0
}

func newMemStore() *memStore {
	return &memStore{recovery: make(map[string][]byte), leader: make(map[string][]byte)}
}

func (s *memStore) PutRecovery(groupKey, blob []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(blob))
	copy(cp, blob)
	s.recovery[string(groupKey)] = cp
	return nil
}

func (s *memStore) GetRecovery(groupKey []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, ok := s.recovery[string(groupKey)]
	if !ok {
		return nil, ErrNotFound
	}
	return blob, nil
}

func (s *memStore) Has(groupKey []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.recovery[string(groupKey)]
	return ok, nil
}

func (s *memStore) List() ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([][]byte, 0, len(s.recovery))
	for k := range s.recovery {
		keys = append(keys, []byte(k))
	}
	return keys, nil
}

func (s *memStore) PutLeaderSecret(label string, a0 []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(a0))
	copy(cp, a0)
	s.leader[label] = cp
	return nil
}

func (s *memStore) GetLeaderSecret(label string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a0, ok := s.leader[label]
	if !ok {
		return nil, ErrNotFound
	}
	return a0, nil
}

func (s *memStore) Close() error { return nil }
