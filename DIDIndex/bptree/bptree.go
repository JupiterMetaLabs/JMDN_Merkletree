// Package bptree implements a B+ Tree for uint64 DID nonces.
//
// All values live in leaves; internal nodes hold only separator keys.
// Leaves form a sorted linked list for O(n) sequential scan.
// Lookup/Insert: O(log n). Merge: O(n log n) via sequential iteration.
//
// With leafMax=128, a tree of 1B keys has ~4 levels and ~8–16 GB RAM.
package bptree

import (
	"sort"

	didindex "github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex"
)

const (
	leafMax = 128 // max keys per leaf before split
	intMax  = 128 // max children per internal node before split
)

// ─── node interface ──────────────────────────────────────────────────────────

type node interface {
	search(key uint64) bool
	// insert returns (splitKey, newRight) when the node splits; zero/nil otherwise.
	// added reports whether a new entry was created.
	insert(key uint64) (splitKey uint64, right node, added bool)
	smallest() uint64
	walk(f func(uint64))
}

// ─── leaf ────────────────────────────────────────────────────────────────────

type leaf struct {
	keys []uint64
	next *leaf
}

func (l *leaf) search(key uint64) bool {
	i := sort.Search(len(l.keys), func(i int) bool { return l.keys[i] >= key })
	return i < len(l.keys) && l.keys[i] == key
}

func (l *leaf) insert(key uint64) (uint64, node, bool) {
	i := sort.Search(len(l.keys), func(i int) bool { return l.keys[i] >= key })
	if i < len(l.keys) && l.keys[i] == key {
		return 0, nil, false // duplicate
	}
	l.keys = append(l.keys, 0)
	copy(l.keys[i+1:], l.keys[i:])
	l.keys[i] = key

	if len(l.keys) <= leafMax {
		return 0, nil, true
	}

	// Split: left keeps [:mid], right gets [mid:]
	mid := len(l.keys) / 2
	right := &leaf{
		keys: make([]uint64, len(l.keys)-mid),
		next: l.next,
	}
	copy(right.keys, l.keys[mid:])
	l.keys = l.keys[:mid]
	l.next = right
	return right.keys[0], right, true
}

func (l *leaf) smallest() uint64 { return l.keys[0] }

func (l *leaf) walk(f func(uint64)) {
	for _, k := range l.keys {
		f(k)
	}
}

// ─── internal ────────────────────────────────────────────────────────────────

type internal struct {
	// n children, n-1 separators; seps[i] = smallest key in children[i+1]
	seps     []uint64
	children []node
}

func (nd *internal) search(key uint64) bool {
	i := sort.Search(len(nd.seps), func(i int) bool { return nd.seps[i] > key })
	return nd.children[i].search(key)
}

func (nd *internal) insert(key uint64) (uint64, node, bool) {
	i := sort.Search(len(nd.seps), func(i int) bool { return nd.seps[i] > key })
	splitKey, right, added := nd.children[i].insert(key)
	if right == nil {
		return 0, nil, added
	}
	// Child split: absorb new separator and right child at position i
	nd.seps = append(nd.seps, 0)
	copy(nd.seps[i+1:], nd.seps[i:])
	nd.seps[i] = splitKey

	nd.children = append(nd.children, nil)
	copy(nd.children[i+2:], nd.children[i+1:])
	nd.children[i+1] = right

	if len(nd.children) <= intMax {
		return 0, nil, added
	}

	// Split internal node
	mid := len(nd.children) / 2
	promoted := nd.seps[mid-1]

	rightNode := &internal{
		seps:     make([]uint64, len(nd.seps)-mid),
		children: make([]node, len(nd.children)-mid),
	}
	copy(rightNode.seps, nd.seps[mid:])
	copy(rightNode.children, nd.children[mid:])

	nd.seps = nd.seps[:mid-1]
	nd.children = nd.children[:mid]

	return promoted, rightNode, added
}

func (nd *internal) smallest() uint64 { return nd.children[0].smallest() }

func (nd *internal) walk(f func(uint64)) {
	for _, c := range nd.children {
		c.walk(f)
	}
}

// ─── BPTree ──────────────────────────────────────────────────────────────────

// BPTree is the B+ Tree index.
type BPTree struct {
	root node
	size int
}

func New() *BPTree { return &BPTree{} }

func (t *BPTree) Name() string { return "B+ Tree" }
func (t *BPTree) Len() int     { return t.size }

func (t *BPTree) Insert(nonce uint64) {
	if t.root == nil {
		t.root = &leaf{keys: []uint64{nonce}}
		t.size++
		return
	}
	splitKey, right, added := t.root.insert(nonce)
	if added {
		t.size++
	}
	if right != nil {
		// Root split: create new root
		t.root = &internal{
			seps:     []uint64{splitKey},
			children: []node{t.root, right},
		}
	}
}

func (t *BPTree) Contains(nonce uint64) bool {
	if t.root == nil {
		return false
	}
	return t.root.search(nonce)
}

func (t *BPTree) Merge(other didindex.DIDIndex) { other.Iter(t.Insert) }

func (t *BPTree) Iter(f func(uint64)) {
	if t.root == nil {
		return
	}
	// Walk the leaf linked list directly for O(n) sequential scan
	n := t.root
	for {
		if l, ok := n.(*leaf); ok {
			for cur := l; cur != nil; cur = cur.next {
				for _, k := range cur.keys {
					f(k)
				}
			}
			return
		}
		n = n.(*internal).children[0]
	}
}

var _ didindex.DIDIndex = (*BPTree)(nil)
