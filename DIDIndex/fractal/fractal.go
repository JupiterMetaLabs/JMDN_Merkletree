// Package fractal implements a Fractal Tree (Message-Buffer B-tree) for uint64
// DID nonces.
//
// A Fractal Tree extends a B-tree by adding a message buffer to each internal
// node. Insertions are written to the root buffer; when a buffer is full it is
// "flushed" one level down in a cascade. This amortises write amplification
// across many inserts rather than paying it per-key.
//
//   Write amplification: O(log² n / B)  — significantly lower than B+ Tree
//   Read:  O(log n + B)                 — check buffer on every level
//   Merge: O(n log n) via iteration
//
// With fractalOrder=32 and bufferCap=128, the fractal tree exhibits good
// write throughput while keeping read cost manageable for DID sync queries.
//
// Reference: Bender et al., "An Introduction to B^ε-trees and Write-Optimized
// Data Structures", login; USENIX Mag. 2015.
package fractal

import (
	"sort"

	didindex "github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex"
)

const (
	fractalOrder = 32  // max children per internal node
	bufferCap    = 128 // max pending messages per internal node before flush
	leafMax      = 64  // max keys per leaf before split
)

// ─── node interface ──────────────────────────────────────────────────────────

type fNode interface {
	search(key uint64) bool
	// applyMsgs inserts a sorted, deduplicated batch of new keys (guaranteed
	// not already present in the subtree) into the subtree.
	// Returns (updated-node, promoted-separator, right-sibling).
	applyMsgs(msgs []uint64) (fNode, uint64, fNode)
	walk(f func(uint64))
}

// ─── leaf ────────────────────────────────────────────────────────────────────

type fLeaf struct {
	keys []uint64 // sorted
}

func (l *fLeaf) search(key uint64) bool {
	i := sort.Search(len(l.keys), func(i int) bool { return l.keys[i] >= key })
	return i < len(l.keys) && l.keys[i] == key
}

func (l *fLeaf) applyMsgs(msgs []uint64) (fNode, uint64, fNode) {
	l.keys = sortedMerge(l.keys, msgs)
	if len(l.keys) <= leafMax {
		return l, 0, nil
	}
	mid := len(l.keys) / 2
	right := &fLeaf{keys: make([]uint64, len(l.keys)-mid)}
	copy(right.keys, l.keys[mid:])
	l.keys = l.keys[:mid]
	return l, right.keys[0], right
}

func (l *fLeaf) walk(f func(uint64)) {
	for _, k := range l.keys {
		f(k)
	}
}

// sortedMerge merges two sorted slices (both already deduplicated internally;
// no cross-dedup needed because applyMsgs only receives new keys).
func sortedMerge(a, b []uint64) []uint64 {
	out := make([]uint64, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] <= b[j] {
			out = append(out, a[i])
			i++
		} else {
			out = append(out, b[j])
			j++
		}
	}
	out = append(out, a[i:]...)
	out = append(out, b[j:]...)
	return out
}

// ─── internal node ───────────────────────────────────────────────────────────

type fInternal struct {
	seps     []uint64 // len = len(children)-1
	children []fNode
	buffer   []uint64 // pending messages, kept sorted
}

func (nd *fInternal) search(key uint64) bool {
	// Check buffer first (bounded by bufferCap)
	for _, k := range nd.buffer {
		if k == key {
			return true
		}
	}
	i := sort.Search(len(nd.seps), func(i int) bool { return nd.seps[i] > key })
	return nd.children[i].search(key)
}

func (nd *fInternal) applyMsgs(msgs []uint64) (fNode, uint64, fNode) {
	nd.buffer = sortedMerge(nd.buffer, msgs)

	if len(nd.buffer) < bufferCap {
		return nd, 0, nil
	}

	nd.flush()

	if len(nd.children) <= fractalOrder {
		return nd, 0, nil
	}

	// Split internal node
	mid := len(nd.children) / 2
	promoted := nd.seps[mid-1]

	right := &fInternal{
		seps:     append([]uint64{}, nd.seps[mid:]...),
		children: append([]fNode{}, nd.children[mid:]...),
	}
	nd.seps = nd.seps[:mid-1]
	nd.children = nd.children[:mid]

	return nd, promoted, right
}

// flush partitions the buffer across children and pushes each group down.
func (nd *fInternal) flush() {
	groups := make([][]uint64, len(nd.children))
	for _, k := range nd.buffer {
		ci := sort.Search(len(nd.seps), func(i int) bool { return nd.seps[i] > k })
		groups[ci] = append(groups[ci], k)
	}
	nd.buffer = nd.buffer[:0]

	for i := len(groups) - 1; i >= 0; i-- {
		if len(groups[i]) == 0 {
			continue
		}
		updated, splitKey, sibling := nd.children[i].applyMsgs(groups[i])
		nd.children[i] = updated
		if sibling != nil {
			nd.seps = append(nd.seps, 0)
			copy(nd.seps[i+1:], nd.seps[i:])
			nd.seps[i] = splitKey

			nd.children = append(nd.children, nil)
			copy(nd.children[i+2:], nd.children[i+1:])
			nd.children[i+1] = sibling
		}
	}
}

func (nd *fInternal) walk(f func(uint64)) {
	// Merge buffer with children walk in sorted order
	var buf []uint64
	buf = append(buf, nd.buffer...)
	for _, c := range nd.children {
		c.walk(func(k uint64) { buf = append(buf, k) })
	}
	sort.Slice(buf, func(i, j int) bool { return buf[i] < buf[j] })
	for _, k := range buf {
		f(k)
	}
}

// ─── FractalTree ─────────────────────────────────────────────────────────────

// FractalTree is the Fractal Tree (write-optimised B-tree) index.
type FractalTree struct {
	root fNode
	size int
}

func New() *FractalTree { return &FractalTree{} }

func (t *FractalTree) Name() string { return "Fractal Tree (Bε-tree)" }
func (t *FractalTree) Len() int     { return t.size }

func (t *FractalTree) Insert(nonce uint64) {
	// Existence check first: avoids double-counting across buffer and leaf levels.
	if t.Contains(nonce) {
		return
	}
	t.size++
	if t.root == nil {
		t.root = &fLeaf{keys: []uint64{nonce}}
		return
	}
	updated, splitKey, sibling := t.root.applyMsgs([]uint64{nonce})
	if sibling != nil {
		t.root = &fInternal{
			seps:     []uint64{splitKey},
			children: []fNode{updated, sibling},
		}
	} else {
		t.root = updated
	}
}

func (t *FractalTree) Contains(nonce uint64) bool {
	if t.root == nil {
		return false
	}
	return t.root.search(nonce)
}

func (t *FractalTree) Merge(other didindex.DIDIndex) { other.Iter(t.Insert) }

func (t *FractalTree) Iter(f func(uint64)) {
	if t.root != nil {
		t.root.walk(f)
	}
}

var _ didindex.DIDIndex = (*FractalTree)(nil)
