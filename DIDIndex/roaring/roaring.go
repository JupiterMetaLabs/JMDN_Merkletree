// Package roaring implements a Roaring Bitmap for uint64 DID nonces.
//
// The uint64 key space is partitioned by the high 48 bits into containers.
// Each container covers 65536 values (low 16 bits) and uses one of two
// internal representations:
//   - arrayContainer: sorted []uint16 — efficient for sparse sets (<4096 values)
//   - bitmapContainer: [1024]uint64   — efficient for dense sets (≥4096 values)
//
// Containers are stored in a hash map for O(1) insert/lookup regardless of
// whether keys are sequential (dense containers) or random (sparse containers).
// Sorted iteration is provided by sorting container keys on first Iter call
// (lazy, cached until the next mutation).
//
// Reference: Chambi et al., "Better bitmap performance with Roaring Bitmaps", 2016.
package roaring

import (
	"sort"

	didindex "github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex"
)

const arrayThreshold = 4096 // promote array→bitmap at this density

// ─── container interface ─────────────────────────────────────────────────────

type container interface {
	add(val uint16) (container, bool) // returns (updated, wasNew)
	has(val uint16) bool
	count() int
	iter(f func(uint16))
	orWith(other container) container
}

// ─── arrayContainer ──────────────────────────────────────────────────────────

type arrayContainer struct {
	vals []uint16 // sorted
}

func (ac *arrayContainer) add(val uint16) (container, bool) {
	i := sort.Search(len(ac.vals), func(i int) bool { return ac.vals[i] >= val })
	if i < len(ac.vals) && ac.vals[i] == val {
		return ac, false
	}
	ac.vals = append(ac.vals, 0)
	copy(ac.vals[i+1:], ac.vals[i:])
	ac.vals[i] = val
	if len(ac.vals) >= arrayThreshold {
		return ac.promote(), true
	}
	return ac, true
}

func (ac *arrayContainer) promote() *bitmapContainer {
	bc := &bitmapContainer{}
	for _, v := range ac.vals {
		bc.bits[v>>6] |= 1 << (v & 63)
		bc.n++
	}
	return bc
}

func (ac *arrayContainer) has(val uint16) bool {
	i := sort.Search(len(ac.vals), func(i int) bool { return ac.vals[i] >= val })
	return i < len(ac.vals) && ac.vals[i] == val
}

func (ac *arrayContainer) count() int { return len(ac.vals) }

func (ac *arrayContainer) iter(f func(uint16)) {
	for _, v := range ac.vals {
		f(v)
	}
}

func (ac *arrayContainer) orWith(other container) container {
	var otherVals []uint16
	other.iter(func(v uint16) { otherVals = append(otherVals, v) })
	merged := mergeSortedUint16(ac.vals, otherVals)
	if len(merged) >= arrayThreshold {
		bc := &bitmapContainer{}
		for _, v := range merged {
			bc.bits[v>>6] |= 1 << (v & 63)
			bc.n++
		}
		return bc
	}
	return &arrayContainer{vals: merged}
}

func mergeSortedUint16(a, b []uint16) []uint16 {
	out := make([]uint16, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			out = append(out, a[i])
			i++
		case a[i] > b[j]:
			out = append(out, b[j])
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	out = append(out, a[i:]...)
	out = append(out, b[j:]...)
	return out
}

// ─── bitmapContainer ─────────────────────────────────────────────────────────

type bitmapContainer struct {
	bits [1024]uint64
	n    int
}

func (bc *bitmapContainer) add(val uint16) (container, bool) {
	w, m := val>>6, uint64(1)<<(val&63)
	if bc.bits[w]&m != 0 {
		return bc, false
	}
	bc.bits[w] |= m
	bc.n++
	return bc, true
}

func (bc *bitmapContainer) has(val uint16) bool {
	return bc.bits[val>>6]&(1<<(val&63)) != 0
}

func (bc *bitmapContainer) count() int { return bc.n }

func (bc *bitmapContainer) iter(f func(uint16)) {
	for i, w := range bc.bits {
		for w != 0 {
			lsb := w & (-w)
			f(uint16(i*64 + bits64Ctz(lsb)))
			w ^= lsb
		}
	}
}

func bits64Ctz(x uint64) int {
	n := 0
	if x&0xffffffff == 0 {
		n += 32
		x >>= 32
	}
	if x&0xffff == 0 {
		n += 16
		x >>= 16
	}
	if x&0xff == 0 {
		n += 8
		x >>= 8
	}
	if x&0xf == 0 {
		n += 4
		x >>= 4
	}
	if x&0x3 == 0 {
		n += 2
		x >>= 2
	}
	if x&0x1 == 0 {
		n++
	}
	return n
}

func (bc *bitmapContainer) orWith(other container) container {
	out := &bitmapContainer{bits: bc.bits}
	other.iter(func(v uint16) { out.bits[v>>6] |= 1 << (v & 63) })
	out.n = 0
	for _, w := range out.bits {
		out.n += popcount64(w)
	}
	return out
}

func popcount64(x uint64) int {
	x -= (x >> 1) & 0x5555555555555555
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
	return int((x * 0x0101010101010101) >> 56)
}

// ─── Roaring ─────────────────────────────────────────────────────────────────

// Roaring is the Roaring Bitmap index.
// Key split: high 48 bits → container key, low 16 bits → bit position.
// Containers are stored in a map for O(1) insert/lookup on both sequential
// and random uint64 keys. Sorted keys are cached lazily for Iter.
type Roaring struct {
	cm         map[uint64]container // container key → container
	sortedKeys []uint64             // sorted keys cache (rebuilt on mutation)
	keysValid  bool
	size       int
}

func New() *Roaring { return &Roaring{cm: make(map[uint64]container)} }

func (r *Roaring) Name() string { return "Roaring Bitmap" }
func (r *Roaring) Len() int     { return r.size }

func splitKey(nonce uint64) (uint64, uint16) {
	return nonce >> 16, uint16(nonce & 0xFFFF)
}

func (r *Roaring) Insert(nonce uint64) {
	hi, lo := splitKey(nonce)
	c := r.cm[hi]
	if c == nil {
		c = &arrayContainer{}
	}
	var added bool
	r.cm[hi], added = c.add(lo)
	if added {
		r.size++
		r.keysValid = false
	}
}

func (r *Roaring) Contains(nonce uint64) bool {
	hi, lo := splitKey(nonce)
	c := r.cm[hi]
	if c == nil {
		return false
	}
	return c.has(lo)
}

// Merge performs a container-level OR: O(containers) rather than O(keys).
func (r *Roaring) Merge(other didindex.DIDIndex) {
	if o, ok := other.(*Roaring); ok {
		r.mergeRoaring(o)
		return
	}
	other.Iter(r.Insert)
}

func (r *Roaring) mergeRoaring(other *Roaring) {
	for hi, oc := range other.cm {
		c := r.cm[hi]
		if c == nil {
			r.size += oc.count()
			r.cm[hi] = oc
		} else {
			old := c.count()
			merged := c.orWith(oc)
			r.cm[hi] = merged
			r.size += merged.count() - old
		}
	}
	r.keysValid = false
}

func (r *Roaring) sortKeys() {
	if r.keysValid {
		return
	}
	r.sortedKeys = r.sortedKeys[:0]
	for k := range r.cm {
		r.sortedKeys = append(r.sortedKeys, k)
	}
	sort.Slice(r.sortedKeys, func(i, j int) bool { return r.sortedKeys[i] < r.sortedKeys[j] })
	r.keysValid = true
}

func (r *Roaring) Iter(f func(uint64)) {
	r.sortKeys()
	for _, hi := range r.sortedKeys {
		base := hi << 16
		r.cm[hi].iter(func(lo uint16) { f(base | uint64(lo)) })
	}
}

var _ didindex.DIDIndex = (*Roaring)(nil)
