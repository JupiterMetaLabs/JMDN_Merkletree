// Package didindex defines the common interface for DID nonce index implementations.
//
// Nonces are uint64 values: high bits = nanosecond timestamp, low bits = random suffix.
// All implementations support Insert, Contains, Merge, and sorted iteration.
package didindex

// DIDIndex is the common interface for all DID nonce index algorithms.
type DIDIndex interface {
	// Insert adds nonce to the index (no-op if already present).
	Insert(nonce uint64)
	// Contains reports whether nonce is in the index.
	Contains(nonce uint64) bool
	// Merge absorbs all entries from other into this index.
	Merge(other DIDIndex)
	// Len returns the number of distinct nonces stored.
	Len() int
	// Name returns the algorithm name for reporting.
	Name() string
	// Iter calls f for each stored nonce in ascending order.
	Iter(f func(uint64))
}
