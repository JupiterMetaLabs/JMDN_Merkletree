// Package hybrid implements the Recommended Index from the comparison document:
//
//	Layer 1 — B+ Tree (disk index): maps epoch (high 32 bits of nonce) to a
//	           Roaring Bitmap container covering the low 32 bits.
//	Layer 2 — Roaring Bitmap containers: each covers 65536 consecutive nonces
//	           stored as 8 KB bitmap pages.
//
// Performance for 1B sequential nanosecond nonces:
//
//	Memory:  ~120 MB – 2 GB (vs. 8–80 GB for pure ART / B+ Tree)
//	Lookup:  O(log n)  — B+ Tree traversal + one bitmap word check
//	Insert:  O(log n)  — same path
//	Merge:   microseconds per matching epoch — container-level OR
//
// The B+ Tree is keyed by the high 32 bits (epoch ≈ ~4-second windows for
// nanosecond timestamps). Within each epoch, a Roaring Bitmap holds the
// low 32 bits using array containers for sparse epochs and 512 KB bitmap
// containers for dense epochs.
package hybrid

import (
	"sort"

	didindex "github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex"
)

// ─── Roaring container (low 32 bits) ─────────────────────────────────────────

const (
	arrayMax = 4096 // promote array→bitmap at this density
)

// roaringChunk covers the low 32 bits of a nonce within one epoch.
// Split further: high 16 bits → slot, low 16 bits → bit in 8KB bitmap or sorted array.
type roaringChunk struct {
	// slot → container (nil = empty)
	slotKeys   []uint16
	containers []innerContainer
	total      int
}

type innerContainer interface {
	add(bit uint16) (innerContainer, bool)
	has(bit uint16) bool
	count() int
	iter(f func(uint16))
	or(other innerContainer) innerContainer
}

// arrayInner: sparse container, sorted uint16 slice.
type arrayInner struct{ vals []uint16 }

func (a *arrayInner) add(bit uint16) (innerContainer, bool) {
	i := sort.Search(len(a.vals), func(i int) bool { return a.vals[i] >= bit })
	if i < len(a.vals) && a.vals[i] == bit {
		return a, false
	}
	a.vals = append(a.vals, 0)
	copy(a.vals[i+1:], a.vals[i:])
	a.vals[i] = bit
	if len(a.vals) >= arrayMax {
		return a.promote(), true
	}
	return a, true
}

func (a *arrayInner) promote() *bitmapInner {
	bc := &bitmapInner{}
	for _, v := range a.vals {
		bc.bits[v>>6] |= 1 << (v & 63)
		bc.n++
	}
	return bc
}

func (a *arrayInner) has(bit uint16) bool {
	i := sort.Search(len(a.vals), func(i int) bool { return a.vals[i] >= bit })
	return i < len(a.vals) && a.vals[i] == bit
}
func (a *arrayInner) count() int { return len(a.vals) }
func (a *arrayInner) iter(f func(uint16)) {
	for _, v := range a.vals {
		f(v)
	}
}
func (a *arrayInner) or(other innerContainer) innerContainer {
	out := &arrayInner{}
	a.iter(func(v uint16) { out.vals = append(out.vals, v) })
	other.iter(func(v uint16) {
		i := sort.Search(len(out.vals), func(i int) bool { return out.vals[i] >= v })
		if i < len(out.vals) && out.vals[i] == v {
			return
		}
		out.vals = append(out.vals, 0)
		copy(out.vals[i+1:], out.vals[i:])
		out.vals[i] = v
	})
	if len(out.vals) >= arrayMax {
		return out.promote()
	}
	return out
}

// bitmapInner: dense container, 8KB bitmap.
type bitmapInner struct {
	bits [1024]uint64
	n    int
}

func (b *bitmapInner) add(bit uint16) (innerContainer, bool) {
	w, m := bit>>6, uint64(1)<<(bit&63)
	if b.bits[w]&m != 0 {
		return b, false
	}
	b.bits[w] |= m
	b.n++
	return b, true
}
func (b *bitmapInner) has(bit uint16) bool {
	return b.bits[bit>>6]&(1<<(bit&63)) != 0
}
func (b *bitmapInner) count() int { return b.n }
func (b *bitmapInner) iter(f func(uint16)) {
	for i, w := range b.bits {
		for w != 0 {
			bit := w & (-w)
			tz := trailingZeros(bit)
			f(uint16(i*64 + tz))
			w ^= bit
		}
	}
}
func (b *bitmapInner) or(other innerContainer) innerContainer {
	out := &bitmapInner{bits: b.bits}
	other.iter(func(v uint16) {
		out.bits[v>>6] |= 1 << (v & 63)
	})
	out.n = 0
	for _, w := range out.bits {
		out.n += popcount(w)
	}
	return out
}

func trailingZeros(x uint64) int {
	n := 0
	for x&1 == 0 {
		n++
		x >>= 1
	}
	return n
}

func popcount(x uint64) int {
	x -= (x >> 1) & 0x5555555555555555
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
	return int((x * 0x0101010101010101) >> 56)
}

// roaringChunk operations

func (rc *roaringChunk) splitLow32(lo32 uint32) (uint16, uint16) {
	return uint16(lo32 >> 16), uint16(lo32 & 0xFFFF)
}

func (rc *roaringChunk) findSlot(hi16 uint16) (int, bool) {
	i := sort.Search(len(rc.slotKeys), func(i int) bool { return rc.slotKeys[i] >= hi16 })
	return i, i < len(rc.slotKeys) && rc.slotKeys[i] == hi16
}

func (rc *roaringChunk) add(lo32 uint32) bool {
	hi16, lo16 := rc.splitLow32(lo32)
	i, found := rc.findSlot(hi16)
	if !found {
		// Insert new slot
		rc.slotKeys = append(rc.slotKeys, 0)
		copy(rc.slotKeys[i+1:], rc.slotKeys[i:])
		rc.slotKeys[i] = hi16
		rc.containers = append(rc.containers, nil)
		copy(rc.containers[i+1:], rc.containers[i:])
		rc.containers[i] = &arrayInner{}
	}
	var added bool
	rc.containers[i], added = rc.containers[i].add(lo16)
	if added {
		rc.total++
	}
	return added
}

func (rc *roaringChunk) has(lo32 uint32) bool {
	hi16, lo16 := rc.splitLow32(lo32)
	i, found := rc.findSlot(hi16)
	if !found {
		return false
	}
	return rc.containers[i].has(lo16)
}

func (rc *roaringChunk) orWith(other *roaringChunk) {
	for i, hi := range other.slotKeys {
		j, found := rc.findSlot(hi)
		if found {
			oldN := rc.containers[j].count()
			rc.containers[j] = rc.containers[j].or(other.containers[i])
			rc.total += rc.containers[j].count() - oldN
		} else {
			rc.slotKeys = append(rc.slotKeys, 0)
			copy(rc.slotKeys[j+1:], rc.slotKeys[j:])
			rc.slotKeys[j] = hi
			rc.containers = append(rc.containers, nil)
			copy(rc.containers[j+1:], rc.containers[j:])
			rc.containers[j] = other.containers[i]
			rc.total += other.containers[i].count()
		}
	}
}

func (rc *roaringChunk) iter(f func(uint32)) {
	for i, hi := range rc.slotKeys {
		base := uint32(hi) << 16
		rc.containers[i].iter(func(lo uint16) {
			f(base | uint32(lo))
		})
	}
}

// ─── B+ Tree over epochs ──────────────────────────────────────────────────────

const bpMax = 64 // max children per internal node

type bpNode interface {
	lookup(epoch uint32) *roaringChunk
	upsert(epoch uint32, chunk *roaringChunk) (bpNode, uint32, bpNode)
	walkChunks(f func(uint32, *roaringChunk))
}

type bpLeafH struct {
	epochs []uint32
	chunks []*roaringChunk
}

func (l *bpLeafH) lookup(epoch uint32) *roaringChunk {
	i := sort.Search(len(l.epochs), func(i int) bool { return l.epochs[i] >= epoch })
	if i < len(l.epochs) && l.epochs[i] == epoch {
		return l.chunks[i]
	}
	return nil
}

func (l *bpLeafH) upsert(epoch uint32, chunk *roaringChunk) (bpNode, uint32, bpNode) {
	i := sort.Search(len(l.epochs), func(i int) bool { return l.epochs[i] >= epoch })
	if i < len(l.epochs) && l.epochs[i] == epoch {
		l.chunks[i] = chunk
		return l, 0, nil
	}
	l.epochs = append(l.epochs, 0)
	copy(l.epochs[i+1:], l.epochs[i:])
	l.epochs[i] = epoch
	l.chunks = append(l.chunks, nil)
	copy(l.chunks[i+1:], l.chunks[i:])
	l.chunks[i] = chunk
	if len(l.epochs) <= bpMax {
		return l, 0, nil
	}
	mid := len(l.epochs) / 2
	right := &bpLeafH{
		epochs: append([]uint32{}, l.epochs[mid:]...),
		chunks: append([]*roaringChunk{}, l.chunks[mid:]...),
	}
	l.epochs = l.epochs[:mid]
	l.chunks = l.chunks[:mid]
	return l, right.epochs[0], right
}

func (l *bpLeafH) walkChunks(f func(uint32, *roaringChunk)) {
	for i, ep := range l.epochs {
		f(ep, l.chunks[i])
	}
}

type bpInternalH struct {
	seps     []uint32
	children []bpNode
}

func (nd *bpInternalH) lookup(epoch uint32) *roaringChunk {
	i := sort.Search(len(nd.seps), func(i int) bool { return nd.seps[i] > epoch })
	return nd.children[i].lookup(epoch)
}

func (nd *bpInternalH) upsert(epoch uint32, chunk *roaringChunk) (bpNode, uint32, bpNode) {
	i := sort.Search(len(nd.seps), func(i int) bool { return nd.seps[i] > epoch })
	updated, splitKey, sibling := nd.children[i].upsert(epoch, chunk)
	nd.children[i] = updated
	if sibling == nil {
		return nd, 0, nil
	}
	nd.seps = append(nd.seps, 0)
	copy(nd.seps[i+1:], nd.seps[i:])
	nd.seps[i] = splitKey
	nd.children = append(nd.children, nil)
	copy(nd.children[i+2:], nd.children[i+1:])
	nd.children[i+1] = sibling
	if len(nd.children) <= bpMax+1 {
		return nd, 0, nil
	}
	mid := len(nd.children) / 2
	promoted := nd.seps[mid-1]
	right := &bpInternalH{
		seps:     append([]uint32{}, nd.seps[mid:]...),
		children: append([]bpNode{}, nd.children[mid:]...),
	}
	nd.seps = nd.seps[:mid-1]
	nd.children = nd.children[:mid]
	return nd, promoted, right
}

func (nd *bpInternalH) walkChunks(f func(uint32, *roaringChunk)) {
	for _, c := range nd.children {
		c.walkChunks(f)
	}
}

// ─── Hybrid ──────────────────────────────────────────────────────────────────

// Hybrid is the recommended Roaring Bitmap + B+ Tree index.
type Hybrid struct {
	root bpNode
	size int
}

func New() *Hybrid { return &Hybrid{} }

func (h *Hybrid) Name() string { return "Hybrid (Roaring + B+ Tree) [Recommended]" }
func (h *Hybrid) Len() int     { return h.size }

// splitNonce: high 32 bits = epoch, low 32 bits = position.
func splitNonce(nonce uint64) (uint32, uint32) {
	return uint32(nonce >> 32), uint32(nonce & 0xFFFFFFFF)
}

func (h *Hybrid) Insert(nonce uint64) {
	epoch, lo32 := splitNonce(nonce)

	var chunk *roaringChunk
	if h.root != nil {
		chunk = h.root.lookup(epoch)
	}
	if chunk == nil {
		chunk = &roaringChunk{}
	}

	if chunk.add(lo32) {
		h.size++
		if h.root == nil {
			h.root = &bpLeafH{}
		}
		updated, splitKey, sibling := h.root.upsert(epoch, chunk)
		if sibling != nil {
			h.root = &bpInternalH{
				seps:     []uint32{splitKey},
				children: []bpNode{updated, sibling},
			}
		} else {
			h.root = updated
		}
	}
}

func (h *Hybrid) Contains(nonce uint64) bool {
	if h.root == nil {
		return false
	}
	epoch, lo32 := splitNonce(nonce)
	chunk := h.root.lookup(epoch)
	if chunk == nil {
		return false
	}
	return chunk.has(lo32)
}

// Merge does epoch-aligned container OR when both sides are Hybrid indexes.
func (h *Hybrid) Merge(other didindex.DIDIndex) {
	if o, ok := other.(*Hybrid); ok {
		h.mergeHybrid(o)
		return
	}
	other.Iter(h.Insert)
}

func (h *Hybrid) mergeHybrid(other *Hybrid) {
	if other.root == nil {
		return
	}
	other.root.walkChunks(func(epoch uint32, otherChunk *roaringChunk) {
		var myChunk *roaringChunk
		if h.root != nil {
			myChunk = h.root.lookup(epoch)
		}
		if myChunk == nil {
			myChunk = &roaringChunk{}
		}
		oldTotal := myChunk.total
		myChunk.orWith(otherChunk)
		h.size += myChunk.total - oldTotal

		if h.root == nil {
			h.root = &bpLeafH{}
		}
		updated, splitKey, sibling := h.root.upsert(epoch, myChunk)
		if sibling != nil {
			h.root = &bpInternalH{
				seps:     []uint32{splitKey},
				children: []bpNode{updated, sibling},
			}
		} else {
			h.root = updated
		}
	})
}

func (h *Hybrid) Iter(f func(uint64)) {
	if h.root == nil {
		return
	}
	h.root.walkChunks(func(epoch uint32, chunk *roaringChunk) {
		base := uint64(epoch) << 32
		chunk.iter(func(lo32 uint32) {
			f(base | uint64(lo32))
		})
	})
}

var _ didindex.DIDIndex = (*Hybrid)(nil)
