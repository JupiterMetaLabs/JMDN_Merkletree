package tests

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

func TestMultiBisect(t *testing.T) {
	count := 3000
	cfg := merkletree.Config{BlockMerge: 10}

	// 1. Build Tree A
	hashes := make([]merkletree.Hash32, count)
	for i := 0; i < count; i++ {
		rand.Read(hashes[i][:])
	}
	b1, _ := merkletree.NewBuilder(cfg)
	b1.Push(0, hashes)

	// 2. Build Tree B (Mutated in Multiple Ranges)
	hashes2 := make([]merkletree.Hash32, len(hashes))
	copy(hashes2, hashes)

	// Mutate blocks at different indices
	indices := []int{105, 500, 1500, 1990}
	for _, idx := range indices {
		hashes2[idx][0] ^= 0xFF
		fmt.Printf("Mutated block at index %d\n", idx)
	}

	b2, _ := merkletree.NewBuilder(cfg)
	b2.Push(0, hashes2)

	// 3. Run MultiBisect
	fmt.Println("Running MultiBisect...")
	diffs, err := b1.MultiBisect(b2, 4) // Concurrency 4
	if err != nil {
		t.Fatalf("MultiBisect failed: %v", err)
	}

	// 4. Verify Results
	fmt.Printf("Found %d differing ranges:\n", len(diffs))
	for _, d := range diffs {
		fmt.Printf(" - Range [%d .. %d]\n", d.Start, d.Start+uint64(d.Count)-1)
	}

	if len(diffs) < len(indices) {
		// Because BlockMerge=10, nearby indices might fall in same chunk?
		// 105 -> Chunk 100-109
		// 500 -> Chunk 500-509
		// 1500 -> Chunk 1500-1509
		// 1990 -> Chunk 1990-1999
		// All are far apart. Should find 4 chunks.
		t.Errorf("Expected 4 diff ranges, got %d", len(diffs))
	}

	for _, idx := range indices {
		found := false
		for _, d := range diffs {
			if uint64(idx) >= d.Start && uint64(idx) < d.Start+uint64(d.Count) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Mutated block %d not found in any diff range", idx)
		}
	}
}

func TestMultiBisectUnequalLengths(t *testing.T) {
	// Scenario: Tree A has 2000 blocks, Tree B has 1500 blocks.
	// The first 1500 blocks are identical.
	// MultiBisect should report diffs starting from 1500 to 1999.

	countA := 3000
	countB := 2500
	cfg := merkletree.Config{BlockMerge: 10}

	// 1. Build Tree A (2000)
	fmt.Println("Building Tree A (2000)...")
	hashes := make([]merkletree.Hash32, countA)
	for i := 0; i < countA; i++ {
		rand.Read(hashes[i][:])
	}
	b1, _ := merkletree.NewBuilder(cfg)
	b1.Push(0, hashes)

	// 2. Build Tree B (1500)
	fmt.Println("Building Tree B (1500)...")
	// Mutate blocks at different indices
	indices := []int{1605, 1700, 1990}
	for _, idx := range indices {
		hashes[idx][0] ^= 0xFF
		fmt.Printf("Mutated block at index %d\n", idx)
	}

	// Use same hashes for first 1500
	b2, _ := merkletree.NewBuilder(cfg)
	b2.Push(0, hashes[:countB])

	// 3. Run MultiBisect
	fmt.Println("Running MultiBisect(A, B)...")
	diffs, err := b1.MultiBisect(b2, 1)
	if err != nil {
		t.Fatalf("MultiBisect failed: %v", err)
	}

	//compare with the normal bisect
	start, count, err := b1.Bisect(b2)
	if err != nil {
		t.Fatalf("Bisect failed: %v", err)
	}
	t.Logf("Bisect found difference at start=%d count=%d", start, count)

	// 4. Verify Results
	fmt.Printf("Found %d differing ranges:\n", len(diffs))
	for _, d := range diffs {
		fmt.Printf(" - Range [%d .. %d]\n", d.Start, d.Start+uint64(d.Count)-1)
	}

	// We expect the difference to cover blocks [1500, 1999].
	// However, due to Merkle structure (peaks align at power-of-2 chunks), the "diff" might start at
	// the largest common chunk boundary. For 2000 vs 1500, divergence starts at the boundary after 1280.
	// So we expect ranges >= 1280.
	foundDiff := false
	for _, d := range diffs {
		if d.Start < 1280 {
			t.Errorf("Unexpected diff range starting before 1280: [%d..%d]", d.Start, d.Start+uint64(d.Count)-1)
		}
		if d.Start >= 1280 {
			foundDiff = true
		}
	}

	if !foundDiff {
		t.Error("Did not find any difference >= 1280, expected mismatch for missing blocks.")
	}
}
