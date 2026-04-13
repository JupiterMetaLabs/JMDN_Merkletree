// Package art implements an Adaptive Radix Tree (ART) for uint64 DID nonces.
//
// Lookup is O(k) where k=8 (bytes per uint64), independent of dataset size.
// Four node types (Node4→16→48→256) adapt to the number of children,
// minimising memory for sparse keys. Sequential uint64 nonces share many
// high bytes, so inner nodes quickly grow to Node256 — degrading memory
// efficiency vs. random keys (see doc comparison table).
//
// Path compression is intentionally omitted to keep the implementation
// readable; add a prefix field to each internal node to recover it.
//
// Reference: Leis et al., "The Adaptive Radix Tree", ICDE 2013.
package art

import (
	didindex "github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex"
)

// ─── node interface ──────────────────────────────────────────────────────────

type iNode interface {
	find(b byte) iNode
	set(b byte, child iNode) iNode
	walk(f func(uint64))
}

// ─── leaf ────────────────────────────────────────────────────────────────────

type leaf struct{ key uint64 }

func (l *leaf) find(byte) iNode       { return nil }
func (l *leaf) set(byte, iNode) iNode { return l }
func (l *leaf) walk(f func(uint64))   { f(l.key) }

// ─── node4 ───────────────────────────────────────────────────────────────────

type node4 struct {
	keys     [4]byte
	children [4]iNode
	n        int
}

func (nd *node4) find(b byte) iNode {
	for i := 0; i < nd.n; i++ {
		if nd.keys[i] == b {
			return nd.children[i]
		}
	}
	return nil
}

func (nd *node4) set(b byte, child iNode) iNode {
	for i := 0; i < nd.n; i++ {
		if nd.keys[i] == b {
			nd.children[i] = child
			return nd
		}
	}
	if nd.n < 4 {
		i := nd.n
		for i > 0 && nd.keys[i-1] > b {
			nd.keys[i] = nd.keys[i-1]
			nd.children[i] = nd.children[i-1]
			i--
		}
		nd.keys[i] = b
		nd.children[i] = child
		nd.n++
		return nd
	}
	// Grow to node16
	n16 := &node16{}
	copy(n16.keys[:nd.n], nd.keys[:nd.n])
	copy(n16.children[:nd.n], nd.children[:nd.n])
	n16.n = nd.n
	return n16.set(b, child)
}

func (nd *node4) walk(f func(uint64)) {
	for i := 0; i < nd.n; i++ {
		nd.children[i].walk(f)
	}
}

// ─── node16 ──────────────────────────────────────────────────────────────────

type node16 struct {
	keys     [16]byte
	children [16]iNode
	n        int
}

func (nd *node16) find(b byte) iNode {
	for i := 0; i < nd.n; i++ {
		if nd.keys[i] == b {
			return nd.children[i]
		}
	}
	return nil
}

func (nd *node16) set(b byte, child iNode) iNode {
	for i := 0; i < nd.n; i++ {
		if nd.keys[i] == b {
			nd.children[i] = child
			return nd
		}
	}
	if nd.n < 16 {
		i := nd.n
		for i > 0 && nd.keys[i-1] > b {
			nd.keys[i] = nd.keys[i-1]
			nd.children[i] = nd.children[i-1]
			i--
		}
		nd.keys[i] = b
		nd.children[i] = child
		nd.n++
		return nd
	}
	// Grow to node48
	n48 := &node48{}
	for i := 0; i < nd.n; i++ {
		n48.slots[nd.keys[i]] = uint8(i + 1)
		n48.children[i] = nd.children[i]
	}
	n48.n = nd.n
	return n48.set(b, child)
}

func (nd *node16) walk(f func(uint64)) {
	for i := 0; i < nd.n; i++ {
		nd.children[i].walk(f)
	}
}

// ─── node48 ──────────────────────────────────────────────────────────────────

type node48 struct {
	slots    [256]uint8 // key byte → children slot (1-indexed; 0 = absent)
	children [48]iNode
	n        int
}

func (nd *node48) find(b byte) iNode {
	s := nd.slots[b]
	if s == 0 {
		return nil
	}
	return nd.children[s-1]
}

func (nd *node48) set(b byte, child iNode) iNode {
	if s := nd.slots[b]; s != 0 {
		nd.children[s-1] = child
		return nd
	}
	if nd.n < 48 {
		nd.children[nd.n] = child
		nd.slots[b] = uint8(nd.n + 1)
		nd.n++
		return nd
	}
	// Grow to node256
	n256 := &node256{}
	for i := 0; i < 256; i++ {
		if nd.slots[i] != 0 {
			n256.children[i] = nd.children[nd.slots[i]-1]
		}
	}
	n256.n = 48
	return n256.set(b, child)
}

func (nd *node48) walk(f func(uint64)) {
	// Iterate in byte order for ascending output
	for b := 0; b < 256; b++ {
		if nd.slots[b] != 0 {
			nd.children[nd.slots[b]-1].walk(f)
		}
	}
}

// ─── node256 ─────────────────────────────────────────────────────────────────

type node256 struct {
	children [256]iNode
	n        int
}

func (nd *node256) find(b byte) iNode { return nd.children[b] }
func (nd *node256) set(b byte, child iNode) iNode {
	if nd.children[b] == nil {
		nd.n++
	}
	nd.children[b] = child
	return nd
}

func (nd *node256) walk(f func(uint64)) {
	for i := 0; i < 256; i++ {
		if nd.children[i] != nil {
			nd.children[i].walk(f)
		}
	}
}

// ─── tree ────────────────────────────────────────────────────────────────────

// ART is the Adaptive Radix Tree index.
type ART struct {
	root iNode
	size int
}

func New() *ART { return &ART{} }

func (a *ART) Name() string { return "Adaptive Radix Tree (ART)" }
func (a *ART) Len() int     { return a.size }

// keyByte returns the depth-th byte of k in big-endian order (depth ∈ [0,7]).
func keyByte(k uint64, depth int) byte {
	return byte(k >> (56 - uint(depth)*8))
}

func (a *ART) Insert(nonce uint64) {
	a.root = artInsert(a.root, nonce, 0, &a.size)
}

func artInsert(n iNode, key uint64, depth int, size *int) iNode {
	if n == nil {
		*size++
		return &leaf{key: key}
	}
	if l, ok := n.(*leaf); ok {
		if l.key == key {
			return n // duplicate
		}
		eb := keyByte(l.key, depth)
		nb := keyByte(key, depth)
		if eb == nb {
			// Common byte at this depth: create single-child path node and recurse
			child := artInsert(l, key, depth+1, size)
			nd := &node4{}
			nd.keys[0] = eb
			nd.children[0] = child
			nd.n = 1
			return nd
		}
		// Keys diverge here: expand leaf into a node4 with two leaves
		nd := &node4{}
		if eb < nb {
			nd.keys[0], nd.children[0] = eb, l
			nd.keys[1], nd.children[1] = nb, &leaf{key: key}
		} else {
			nd.keys[0], nd.children[0] = nb, &leaf{key: key}
			nd.keys[1], nd.children[1] = eb, l
		}
		nd.n = 2
		*size++
		return nd
	}
	// Internal node: descend into appropriate child
	b := keyByte(key, depth)
	child := n.find(b)
	newChild := artInsert(child, key, depth+1, size)
	if newChild != child {
		n = n.set(b, newChild)
	}
	return n
}

func (a *ART) Contains(nonce uint64) bool {
	n := a.root
	for depth := 0; n != nil; depth++ {
		if l, ok := n.(*leaf); ok {
			return l.key == nonce
		}
		n = n.find(keyByte(nonce, depth))
	}
	return false
}

func (a *ART) Merge(other didindex.DIDIndex) { other.Iter(a.Insert) }

func (a *ART) Iter(f func(uint64)) {
	if a.root != nil {
		a.root.walk(f)
	}
}

var _ didindex.DIDIndex = (*ART)(nil)
