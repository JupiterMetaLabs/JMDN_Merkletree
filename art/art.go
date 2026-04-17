// Package art implements a production-ready Adaptive Radix Tree (ART) for
// uint64 DID nonces.
//
// Lookup, insert, and delete are O(k) where k=8 (bytes per uint64),
// independent of dataset size. Four node types (Node4→16→48→256) adapt to
// the child count, minimising memory for sparse keys.
//
// Operations:
//   - Insert    — O(k), duplicate-safe
//   - Contains  — O(k)
//   - Delete    — O(k), shrinks node types on the way back up
//   - Merge     — bulk insert from another *ART
//   - Iter      — ascending order walk
//   - Keys      — sorted snapshot as []uint64
//
// All methods are thread-safe via a read/write mutex.
//
// Reference: Leis et al., "The Adaptive Radix Tree", ICDE 2013.
package art

import "sync"

// ─── node interface ───────────────────────────────────────────────────────────

type iNode interface {
	find(b byte) iNode
	set(b byte, child iNode) iNode
	// remove deletes child b and returns the (possibly shrunken/collapsed) node.
	// Returns nil if the caller should delete this node entirely.
	remove(b byte) iNode
	walk(f func(uint64))
}

// ─── leaf ─────────────────────────────────────────────────────────────────────

type leaf struct{ key uint64 }

func (l *leaf) find(byte) iNode       { return nil }
func (l *leaf) set(byte, iNode) iNode { return l }
func (l *leaf) remove(byte) iNode     { return l }
func (l *leaf) walk(f func(uint64))   { f(l.key) }

// ─── node4 ────────────────────────────────────────────────────────────────────

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
	// Grow to node16.
	n16 := &node16{}
	copy(n16.keys[:nd.n], nd.keys[:nd.n])
	copy(n16.children[:nd.n], nd.children[:nd.n])
	n16.n = nd.n
	return n16.set(b, child)
}

func (nd *node4) remove(b byte) iNode {
	for i := 0; i < nd.n; i++ {
		if nd.keys[i] == b {
			// Shift remaining entries left.
			for j := i; j < nd.n-1; j++ {
				nd.keys[j] = nd.keys[j+1]
				nd.children[j] = nd.children[j+1]
			}
			nd.n--
			nd.children[nd.n] = nil
			if nd.n == 1 {
				return nd.children[0] // collapse single-child path node
			}
			return nd
		}
	}
	return nd
}

func (nd *node4) walk(f func(uint64)) {
	for i := 0; i < nd.n; i++ {
		nd.children[i].walk(f)
	}
}

// ─── node16 ───────────────────────────────────────────────────────────────────

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
	// Grow to node48.
	n48 := &node48{}
	for i := 0; i < nd.n; i++ {
		n48.slots[nd.keys[i]] = uint8(i + 1)
		n48.children[i] = nd.children[i]
	}
	n48.n = nd.n
	return n48.set(b, child)
}

func (nd *node16) remove(b byte) iNode {
	for i := 0; i < nd.n; i++ {
		if nd.keys[i] == b {
			for j := i; j < nd.n-1; j++ {
				nd.keys[j] = nd.keys[j+1]
				nd.children[j] = nd.children[j+1]
			}
			nd.n--
			nd.children[nd.n] = nil
			if nd.n <= 4 {
				// Shrink to node4.
				n4 := &node4{}
				copy(n4.keys[:nd.n], nd.keys[:nd.n])
				copy(n4.children[:nd.n], nd.children[:nd.n])
				n4.n = nd.n
				if n4.n == 1 {
					return n4.children[0]
				}
				return n4
			}
			return nd
		}
	}
	return nd
}

func (nd *node16) walk(f func(uint64)) {
	for i := 0; i < nd.n; i++ {
		nd.children[i].walk(f)
	}
}

// ─── node48 ───────────────────────────────────────────────────────────────────

type node48 struct {
	slots    [256]uint8 // key byte → children index (1-indexed; 0 = absent)
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
		// Scan for a free slot (handles holes left by previous removes).
		for slot := 0; slot < 48; slot++ {
			if nd.children[slot] == nil {
				nd.children[slot] = child
				nd.slots[b] = uint8(slot + 1)
				nd.n++
				return nd
			}
		}
	}
	// Grow to node256.
	n256 := &node256{}
	for i := 0; i < 256; i++ {
		if nd.slots[i] != 0 {
			n256.children[i] = nd.children[nd.slots[i]-1]
		}
	}
	n256.n = nd.n
	return n256.set(b, child)
}

func (nd *node48) remove(b byte) iNode {
	s := nd.slots[b]
	if s == 0 {
		return nd
	}
	nd.children[s-1] = nil
	nd.slots[b] = 0
	nd.n--
	if nd.n <= 16 {
		// Shrink to node16.
		n16 := &node16{}
		for i := 0; i < 256; i++ {
			if nd.slots[i] != 0 {
				n16.keys[n16.n] = byte(i)
				n16.children[n16.n] = nd.children[nd.slots[i]-1]
				n16.n++
			}
		}
		return n16
	}
	return nd
}

func (nd *node48) walk(f func(uint64)) {
	for b := 0; b < 256; b++ {
		if nd.slots[b] != 0 {
			nd.children[nd.slots[b]-1].walk(f)
		}
	}
}

// ─── node256 ──────────────────────────────────────────────────────────────────

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

func (nd *node256) remove(b byte) iNode {
	if nd.children[b] == nil {
		return nd
	}
	nd.children[b] = nil
	nd.n--
	if nd.n <= 48 {
		// Shrink to node48.
		n48 := &node48{}
		for i := 0; i < 256; i++ {
			if nd.children[i] != nil {
				n48.children[n48.n] = nd.children[i]
				n48.slots[i] = uint8(n48.n + 1)
				n48.n++
			}
		}
		return n48
	}
	return nd
}

func (nd *node256) walk(f func(uint64)) {
	for i := 0; i < 256; i++ {
		if nd.children[i] != nil {
			nd.children[i].walk(f)
		}
	}
}

// ─── tree operations ──────────────────────────────────────────────────────────

// keyByte returns the depth-th byte of k in big-endian order (depth ∈ [0,7]).
func keyByte(k uint64, depth int) byte {
	if depth < 0 || depth > 7 {
		return 0
	}
	return byte(k >> (56 - uint(depth)*8))
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
			// uint64 keys have exactly 8 bytes (depth 0..7). Past that, keyByte would
			// underflow and compare equal for all keys, causing infinite recursion.
			if depth >= 7 {
				return n
			}
			// Keys share a byte at this depth: create a path node and recurse.
			child := artInsert(l, key, depth+1, size)
			nd := &node4{}
			nd.keys[0] = eb
			nd.children[0] = child
			nd.n = 1
			return nd
		}
		// Keys diverge here: expand into a node4 with two leaves.
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
	b := keyByte(key, depth)
	child := n.find(b)
	newChild := artInsert(child, key, depth+1, size)
	if newChild != child {
		n = n.set(b, newChild)
	}
	return n
}

func artDelete(n iNode, key uint64, depth int, deleted *bool) iNode {
	if n == nil {
		return nil
	}
	if l, ok := n.(*leaf); ok {
		if l.key == key {
			*deleted = true
			return nil
		}
		return n
	}
	b := keyByte(key, depth)
	child := n.find(b)
	if child == nil {
		return n
	}
	newChild := artDelete(child, key, depth+1, deleted)
	if !*deleted {
		return n
	}
	if newChild == nil {
		// Child was removed — delete its slot and potentially shrink this node.
		return n.remove(b)
	}
	if newChild != child {
		n = n.set(b, newChild)
	}
	return n
}

// ─── ART ──────────────────────────────────────────────────────────────────────

// ART is a thread-safe Adaptive Radix Tree for uint64 keys.
type ART struct {
	root iNode
	size int
	mu   sync.RWMutex
}

// New returns an empty ART.
func New() *ART { return &ART{} }

// Len returns the number of distinct keys in the index.
func (a *ART) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.size
}

// Insert adds nonce to the index. Duplicate inserts are silently ignored.
func (a *ART) Insert(nonce uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.root = artInsert(a.root, nonce, 0, &a.size)
}

// Contains returns true if nonce is present in the index.
func (a *ART) Contains(nonce uint64) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := a.root
	for depth := 0; n != nil; depth++ {
		if l, ok := n.(*leaf); ok {
			return l.key == nonce
		}
		n = n.find(keyByte(nonce, depth))
	}
	return false
}

// Delete removes nonce from the index. Returns true if it was present.
// Node types are shrunk on the way back up (node256→48→16→4 as needed),
// and single-child path nodes are collapsed.
func (a *ART) Delete(nonce uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	var deleted bool
	a.root = artDelete(a.root, nonce, 0, &deleted)
	if deleted {
		a.size--
	}
	return deleted
}

// Merge inserts all keys from src into a.
func (a *ART) Merge(src *ART) {
	src.Iter(a.Insert)
}

// Iter calls f for every key in ascending order.
func (a *ART) Iter(f func(uint64)) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.root != nil {
		a.root.walk(f)
	}
}

// Keys returns all keys as a sorted slice.
func (a *ART) Keys() []uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]uint64, 0, a.size)
	if a.root != nil {
		a.root.walk(func(k uint64) { out = append(out, k) })
	}
	return out
}

// Clear removes all keys and resets the index.
func (a *ART) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.root = nil
	a.size = 0
}
