// Package lsm implements a Log-Structured Merge Tree (LSM) for uint64 DID nonces.
//
// Write path: MemTable (sorted slice) → immutable L0 SSTables → merged L1.
// Compaction: when L0 reaches l0Threshold SSTables, they are merged into L1.
// Read path: MemTable → L0 (bloom filter then binary search) → L1 binary search.
//
// Strengths for sequential uint64: excellent write throughput, good compression,
// merge is O(n) via sorted merge. Weakness: read amplification across levels.
package lsm

import (
	"math"
	"sort"

	didindex "github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex"
)

const (
	memTableMax   = 8_192 // flush MemTable to L0 when it reaches this size
	l0Threshold   = 4     // compact L0 into L1 when L0 has this many SSTables
)

// ─── Bloom filter ─────────────────────────────────────────────────────────────

// bloom is a simple Bloom filter using double-hashing.
type bloom struct {
	bits []uint64
	m    int // number of bits (multiple of 64)
	k    int // number of hash functions
}

func newBloom(capacity int, fpRate float64) *bloom {
	m := int(math.Ceil(-float64(capacity) * math.Log(fpRate) / (math.Log(2) * math.Log(2))))
	m = ((m + 63) / 64) * 64
	if m < 64 {
		m = 64
	}
	k := int(math.Round(float64(m) / float64(capacity) * math.Log(2)))
	if k < 1 {
		k = 1
	}
	return &bloom{bits: make([]uint64, m/64), m: m, k: k}
}

// hashPair returns two independent 64-bit hashes of x via FNV-based mixing.
func hashPair(x uint64) (uint64, uint64) {
	h := x ^ (x >> 33)
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h, h*0x9e3779b97f4a7c15 + 0x6c62272e07bb0142
}

func (b *bloom) add(x uint64) {
	h1, h2 := hashPair(x)
	for i := range b.k {
		pos := (h1 + uint64(i)*h2) % uint64(b.m)
		b.bits[pos>>6] |= 1 << (pos & 63)
	}
}

func (b *bloom) has(x uint64) bool {
	h1, h2 := hashPair(x)
	for i := range b.k {
		pos := (h1 + uint64(i)*h2) % uint64(b.m)
		if b.bits[pos>>6]&(1<<(pos&63)) == 0 {
			return false
		}
	}
	return true
}

// ─── SSTable ─────────────────────────────────────────────────────────────────

type sst struct {
	keys []uint64 // sorted
	bf   *bloom
}

func newSST(sorted []uint64) *sst {
	bf := newBloom(len(sorted)+1, 0.01)
	for _, k := range sorted {
		bf.add(k)
	}
	return &sst{keys: sorted, bf: bf}
}

func (s *sst) has(key uint64) bool {
	if !s.bf.has(key) {
		return false
	}
	i := sort.Search(len(s.keys), func(i int) bool { return s.keys[i] >= key })
	return i < len(s.keys) && s.keys[i] == key
}

// ─── LSM ─────────────────────────────────────────────────────────────────────

// LSM is the Log-Structured Merge Tree index.
type LSM struct {
	mem  []uint64 // MemTable: unsorted buffer, sorted on flush
	l0   []*sst   // L0: immutable SSTables (most recent first)
	l1   *sst     // L1: single large merged SSTable
	size int
}

func New() *LSM { return &LSM{} }

func (t *LSM) Name() string { return "LSM Tree" }
func (t *LSM) Len() int     { return t.size }

func (t *LSM) Insert(nonce uint64) {
	// Check for duplicate before inserting
	if t.Contains(nonce) {
		return
	}
	t.mem = append(t.mem, nonce)
	t.size++
	if len(t.mem) >= memTableMax {
		t.flushMem()
		if len(t.l0) >= l0Threshold {
			t.compact()
		}
	}
}

// flushMem sorts the MemTable and appends it as a new L0 SSTable.
func (t *LSM) flushMem() {
	if len(t.mem) == 0 {
		return
	}
	sort.Slice(t.mem, func(i, j int) bool { return t.mem[i] < t.mem[j] })
	t.l0 = append(t.l0, newSST(t.mem))
	t.mem = nil
}

// compact merges all L0 SSTables into L1 using a k-way sorted merge.
func (t *LSM) compact() {
	// Gather all sorted runs: existing l1 + all l0 tables
	runs := make([][]uint64, 0, len(t.l0)+1)
	if t.l1 != nil {
		runs = append(runs, t.l1.keys)
	}
	for _, s := range t.l0 {
		runs = append(runs, s.keys)
	}
	merged := kWayMerge(runs)
	t.l1 = newSST(merged)
	t.l0 = nil
}

// kWayMerge merges k sorted slices into one sorted, deduplicated slice.
func kWayMerge(runs [][]uint64) []uint64 {
	total := 0
	for _, r := range runs {
		total += len(r)
	}
	out := make([]uint64, 0, total)
	// Simple pointer-per-run merge
	ptrs := make([]int, len(runs))
	var prev uint64
	first := true
	for {
		minVal := ^uint64(0)
		minIdx := -1
		for i, r := range runs {
			if ptrs[i] < len(r) && r[ptrs[i]] < minVal {
				minVal = r[ptrs[i]]
				minIdx = i
			}
		}
		if minIdx == -1 {
			break
		}
		ptrs[minIdx]++
		if first || minVal != prev {
			out = append(out, minVal)
			prev = minVal
			first = false
		}
	}
	return out
}

func (t *LSM) Contains(nonce uint64) bool {
	// 1. MemTable (linear scan; small by design)
	for _, k := range t.mem {
		if k == nonce {
			return true
		}
	}
	// 2. L0 SSTables (most recent first)
	for i := len(t.l0) - 1; i >= 0; i-- {
		if t.l0[i].has(nonce) {
			return true
		}
	}
	// 3. L1
	if t.l1 != nil && t.l1.has(nonce) {
		return true
	}
	return false
}

func (t *LSM) Merge(other didindex.DIDIndex) { other.Iter(t.Insert) }

func (t *LSM) Iter(f func(uint64)) {
	// Collect all keys from all levels and sort+deduplicate
	var all []uint64
	all = append(all, t.mem...)
	for _, s := range t.l0 {
		all = append(all, s.keys...)
	}
	if t.l1 != nil {
		all = append(all, t.l1.keys...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	var prev uint64
	for i, k := range all {
		if i == 0 || k != prev {
			f(k)
			prev = k
		}
	}
}

var _ didindex.DIDIndex = (*LSM)(nil)
