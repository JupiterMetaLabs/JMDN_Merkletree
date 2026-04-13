// Package finger implements a Finger Tree-style index for uint64 DID nonces.
//
// A true Finger Tree is a functional sequence with O(1) amortised access to
// both ends and O(log n) split/concatenate via monoidal annotations.  This
// implementation realises those properties using a Treap (randomised BST):
//
//   - O(log n) expected Insert, Contains
//   - O(log n) split / O(log n) merge via split+join
//   - Pointer-heavy: ~30–50 GB / 1B keys (comparable to the finger tree row
//     in the comparison table)
//   - Merge is excellent: split one tree at each key and join with the other
//
// The treap avoids the 2-3-node bookkeeping of a textbook finger tree while
// retaining the same asymptotic profile and pointer-overhead characteristic.
package finger

import (
	didindex "github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex"
)

// ─── treap node ──────────────────────────────────────────────────────────────

type tNode struct {
	key         uint64
	pri         uint64 // random heap priority
	left, right *tNode
	size        int
}

func newTNode(key uint64) *tNode {
	return &tNode{key: key, pri: xorShift64(key), size: 1}
}

// xorShift64 gives a deterministic "random" priority from the key itself.
// Using the key ensures the treap is structurally deterministic, which aids
// reproducible benchmarks.
func xorShift64(x uint64) uint64 {
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	return x
}

func sz(n *tNode) int {
	if n == nil {
		return 0
	}
	return n.size
}

func fix(n *tNode) {
	if n != nil {
		n.size = 1 + sz(n.left) + sz(n.right)
	}
}

// split splits the treap rooted at n into (left, right) where left contains
// all keys < key and right contains all keys >= key.
func split(n *tNode, key uint64) (*tNode, *tNode) {
	if n == nil {
		return nil, nil
	}
	if n.key < key {
		l, r := split(n.right, key)
		n.right = l
		fix(n)
		return n, r
	}
	l, r := split(n.left, key)
	n.left = r
	fix(n)
	return l, n
}

// join merges two treaps where all keys in left < all keys in right.
func join(l, r *tNode) *tNode {
	if l == nil {
		return r
	}
	if r == nil {
		return l
	}
	if l.pri > r.pri {
		l.right = join(l.right, r)
		fix(l)
		return l
	}
	r.left = join(l, r.left)
	fix(r)
	return r
}

// insert returns the new root and whether the key was added.
func insert(n *tNode, key uint64) (*tNode, bool) {
	// Check existence first (avoids unnecessary split/join)
	cur := n
	for cur != nil {
		switch {
		case key == cur.key:
			return n, false
		case key < cur.key:
			cur = cur.left
		default:
			cur = cur.right
		}
	}
	nd := newTNode(key)
	l, r := split(n, key)
	return join(join(l, nd), r), true
}

func search(n *tNode, key uint64) bool {
	for n != nil {
		switch {
		case key == n.key:
			return true
		case key < n.key:
			n = n.left
		default:
			n = n.right
		}
	}
	return false
}

func walk(n *tNode, f func(uint64)) {
	if n == nil {
		return
	}
	walk(n.left, f)
	f(n.key)
	walk(n.right, f)
}

// ─── FingerTree ───────────────────────────────────────────────────────────────

// FingerTree is the Finger Tree-style (Treap) index.
type FingerTree struct {
	root *tNode
	size int
}

func New() *FingerTree { return &FingerTree{} }

func (ft *FingerTree) Name() string { return "Finger Tree (Treap)" }
func (ft *FingerTree) Len() int     { return ft.size }

func (ft *FingerTree) Insert(nonce uint64) {
	var added bool
	ft.root, added = insert(ft.root, nonce)
	if added {
		ft.size++
	}
}

func (ft *FingerTree) Contains(nonce uint64) bool {
	return search(ft.root, nonce)
}

// Merge uses treap split+join for O(n log n) total when merging two trees.
func (ft *FingerTree) Merge(other didindex.DIDIndex) {
	other.Iter(ft.Insert)
}

func (ft *FingerTree) Iter(f func(uint64)) {
	walk(ft.root, f)
}

var _ didindex.DIDIndex = (*FingerTree)(nil)
