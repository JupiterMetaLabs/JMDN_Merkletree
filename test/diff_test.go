package tests

import (
	"crypto/rand"
	"testing"

	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

func TestTreeDiff(t *testing.T) {
	count := 3000
	cfg := merkletree.Config{BlockMerge: 10}

	// 1. Identical Trees
	hashes := make([]merkletree.Hash32, count)
	for i := 0; i < count; i++ {
		rand.Read(hashes[i][:])
	}
	b1, _ := merkletree.NewBuilder(cfg)
	b1.Push(0, hashes)
	b2, _ := merkletree.NewBuilder(cfg)
	b2.Push(0, hashes)

	diffs, err := b1.TreeDiff(b2)
	if err != nil {
		t.Fatalf("TreeDiff failed: %v", err)
	}
	if len(diffs) != 0 {
		t.Errorf("Expected 0 diffs for identical trees, got %d", len(diffs))
	}

	// 2. Single Mismatch [1500]
	hashesMut := make([]merkletree.Hash32, count)
	copy(hashesMut, hashes)
	hashesMut[1500][0] ^= 0xFF
	b3, _ := merkletree.NewBuilder(cfg)
	b3.Push(0, hashesMut)

	diffs, err = b1.TreeDiff(b3)
	if err != nil {
		t.Fatalf("TreeDiff failed: %v", err)
	}
	if len(diffs) != 1 {
		t.Errorf("Expected 1 diff, got %d", len(diffs))
	} else {
		if diffs[0].Start != 1500 {
			t.Errorf("Expected diff start 1500, got %d", diffs[0].Start)
		}
	}

	// 3. Multiple Mismatches [500, 1500]
	hashesMutMulti := make([]merkletree.Hash32, count)
	copy(hashesMutMulti, hashes)
	hashesMutMulti[500][0] ^= 0xFF
	hashesMutMulti[1500][0] ^= 0xFF
	b4, _ := merkletree.NewBuilder(cfg)
	b4.Push(0, hashesMutMulti)

	diffs, err = b1.TreeDiff(b4)
	if err != nil {
		t.Fatalf("TreeDiff failed: %v", err)
	}
	if len(diffs) != 2 {
		t.Errorf("Expected 2 diffs, got %d", len(diffs))
	}

	// 4. Unequal Lengths (Prefix)
	// b1 (3000) vs bSmall (2500)
	// Expect range [2500..2999] as diff
	bSmall, _ := merkletree.NewBuilder(cfg)
	bSmall.Push(0, hashes[:2500])

	diffs, err = b1.TreeDiff(bSmall)
	if err != nil {
		t.Fatalf("TreeDiff failed: %v", err)
	}
	// Depending on chunk boundaries, this might be one large diff or multiple small ones.
	// But it should cover [2500..2999].
	if len(diffs) == 0 {
		t.Fatal("Expected diffs for unequal trees, got 0")
	}
	t.Logf("Unequal length diffs: %d found", len(diffs))
	firstDiff := diffs[0]
	if firstDiff.Start < 2500 {
		// Actually if chunks align, it should start exactly at 2500
		// or slightly before if 2500 is mid-chunk?
		// BlockMerge=10. 2500 is multiple of 10. Should align.
		t.Errorf("Expected diff start >= 2500, got %d", firstDiff.Start)
	}
}

func TestTreeDiff_LargeVsSmall(t *testing.T) {
	// Scenario: A = 3000, B = 200
	// This tests extreme size difference (fault tolerance/reliability).
	countA := 3000
	countB := 200
	cfg := merkletree.Config{BlockMerge: 10}

	hashes := make([]merkletree.Hash32, countA)
	for i := 0; i < countA; i++ {
		rand.Read(hashes[i][:])
	}

	bLarge, _ := merkletree.NewBuilder(cfg)
	bLarge.Push(0, hashes)

	bSmall, _ := merkletree.NewBuilder(cfg)
	bSmall.Push(0, hashes[:countB])

	diffs, err := bLarge.TreeDiff(bSmall)
	if err != nil {
		t.Fatalf("TreeDiff failed: %v", err)
	}

	// Expectation: Diff should cover [200..2999]
	// It relies on how the tree breaks down.
	// Since 200 is likely a clean chunk boundary (BlockMerge=10),
	// we expect the diff to start exactly at 200.
	if len(diffs) == 0 {
		t.Fatal("Expected diffs, got 0")
	}

	t.Logf("Found %d diff ranges", len(diffs))
	for i, d := range diffs {
		t.Logf("Diff %d: [%d..%d]", i, d.Start, d.Start+uint64(d.Count)-1)
	}

	if diffs[0].Start != 200 {
		t.Errorf("Expected first diff to start at 200, got %d", diffs[0].Start)
	}

	// Verify total coverage
	var totalDiff uint64
	for _, d := range diffs {
		totalDiff += uint64(d.Count)
	}
	expectedDiff := uint64(countA - countB)
	if totalDiff != expectedDiff {
		t.Errorf("Expected total diff blocks %d, got %d", expectedDiff, totalDiff)
	}
}

func TestTreeDiff_LargeVsSmall_WithInnerDiffs(t *testing.T) {
	// Scenario: A = 3000, B = 200
	// But B also has differences inside the 0..199 range.
	// This verifies we find BOTH the inner diffs AND the missing tail.
	countA := 3000
	countB := 200
	cfg := merkletree.Config{BlockMerge: 100}

	hashes := make([]merkletree.Hash32, countA)
	for i := 0; i < countA; i++ {
		rand.Read(hashes[i][:])
	}

	bLarge, _ := merkletree.NewBuilder(cfg)
	bLarge.Push(0, hashes)

	// Prepare hashes for B with mutations
	hashesB := make([]merkletree.Hash32, countB)
	copy(hashesB, hashes[:countB])

	// Mutate inside the common range
	hashesB[55][0] ^= 0xFF  // Diff at 55 (chunk 50-59)
	hashesB[155][0] ^= 0xFF // Diff at 155 (chunk 150-159)

	bSmall, _ := merkletree.NewBuilder(cfg)
	bSmall.Push(0, hashesB)

	diffs, err := bLarge.TreeDiff(bSmall)
	if err != nil {
		t.Fatalf("TreeDiff failed: %v", err)
	}

	if len(diffs) == 0 {
		t.Fatal("Expected diffs, got 0")
	}

	t.Logf("Found %d diff ranges", len(diffs))
	for i, d := range diffs {
		t.Logf("Diff %d: [%d..%d]", i, d.Start, d.Start+uint64(d.Count)-1)
	}

	// Verification
	// 1. Check inner diffs
	// 55 falls in [50..59]
	found55 := false
	// 155 falls in [150..159]
	found155 := false

	for _, d := range diffs {
		if d.Start <= 55 && d.Start+uint64(d.Count) > 55 {
			found55 = true
		}
		if d.Start <= 155 && d.Start+uint64(d.Count) > 155 {
			found155 = true
		}
	}

	if !found55 {
		t.Error("Did not find diff for index 55")
	}
	if !found155 {
		t.Error("Did not find diff for index 155")
	}

	// 2. Check missing tail (starts at 200)
	// We expect the sum of diffs >= (3000-200) + inner diffs
	// Actually, the tail diffs should account for 2800 blocks exactly.
	// And inner diffs should account for 10 blocks each (BlockMerge=10).

	var tailBlocks uint64
	for _, d := range diffs {
		if d.Start >= 200 {
			tailBlocks += uint64(d.Count)
		}
	}

	if tailBlocks != 2800 {
		t.Errorf("Expected 2800 tail diff blocks (>=200), got %d", tailBlocks)
	}
}
