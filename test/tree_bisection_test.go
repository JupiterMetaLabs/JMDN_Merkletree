package tests

import (
	"crypto/rand"
	"testing"

	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

func TestTreeBisect(t *testing.T) {
	count := 3500
	// Use a small BlockMerge to force many levels and peaks quickly
	cfg := merkletree.Config{BlockMerge: 10}

	// 1. Build Base Tree
	hashes := make([]merkletree.Hash32, count)
	for i := 0; i < count; i++ {
		rand.Read(hashes[i][:])
	}
	b1, _ := merkletree.NewBuilder(cfg)
	b1.Push(0, hashes)

	// 2. Identical Tree
	b2, _ := merkletree.NewBuilder(cfg)
	b2.Push(0, hashes)

	start, countRet, err := b1.TreeBisect(b2)
	if err != nil {
		t.Fatalf("TreeBisect failed: %v", err)
	}
	if start != 0 || countRet != 0 {
		t.Errorf("Expected identical trees, got diff at start=%d count=%d", start, countRet)
	}

	// 3. Different Tree (Single Mutation)
	hashesMutated := make([]merkletree.Hash32, len(hashes))
	copy(hashesMutated, hashes)
	idx := 1505
	hashesMutated[idx][0] ^= 0xFF

	b3, _ := merkletree.NewBuilder(cfg)
	b3.Push(0, hashesMutated)

	start, countRet, err = b1.TreeBisect(b3)
	if err != nil {
		t.Fatalf("TreeBisect failed: %v", err)
	}

	// We expect the diff range to cover index 1505.
	// Since BlockMerge=10, the leaf chunks are size 10.
	// 1505 falls in chunk [1500..1509].
	// So expected start is 1500, count is 10.
	if start != 1500 && countRet != 10 {
		t.Errorf("Expected diff at start=1500 count=10, got start=%d count=%d", start, countRet)
	} else {
		t.Logf("Success: Correctly identified diff range [%d..%d]", start, start+uint64(countRet)-1)
	}

	// 4. Different Size Trees (3000 vs 2700)
	// The user requested to compare 3000 vs 2700.
	// 'hashes' is already size 3000 (from line 11).

	// Tree A: 3000 blocks
	b1_3000, _ := merkletree.NewBuilder(cfg)
	b1_3000.Push(0, hashes)

	// Tree B: 2700 blocks (Prefix of A)
	countB := 190
	b2_2700, _ := merkletree.NewBuilder(cfg)
	b2_2700.Push(0, hashes[:countB])

	start, countRet, err = b1_3000.TreeBisect(b2_2700)
	if err != nil {
		t.Fatalf("TreeBisect failed: %v", err)
	}

	// b1_3000 (3500) is a PREFIX of bLarge (2890). Actually bLarge is prefix of b1.
	// Wait, b1_3000 was initialized with ALL hashes (3500).
	// b2_2700 (now b2_2890) was initialized with hashes[:2890].

	// So A (3500) vs B (2890).
	// B is a prefix of A.
	// Difference should be the extra blocks in A starting at 2890.
	// TreeBisect returns the first diff range.
	// It should identify that A has content at 2890 where B has nothing.

	t.Logf("Different Size (A=3500, B=2890): Found diff at start=%d count=%d", start, countRet)
	if start != 2890 {
		t.Errorf("Expected diff start at 2890, got %d", start)
	}
	if countRet == 0 {
		t.Error("Expected some difference for unequal trees, got none")
	}
}
