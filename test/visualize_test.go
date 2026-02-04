package tests

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

func TestRandomizedDiff10k(t *testing.T) {
	count := 10000
	blockmerge := math.Ceil(float64(count) * 0.005)
	cfg := merkletree.Config{BlockMerge: int(blockmerge)}

	fmt.Printf("Generating %d random blocks...\n", count)
	hashes := make([]merkletree.Hash32, count)
	for i := 0; i < count; i++ {
		// Just filling with random bytes
		rand.Read(hashes[i][:])
	}

	// 1. Build Tree A
	fmt.Println("Building Tree A...")
	b1, _ := merkletree.NewBuilder(cfg)
	b1.Push(0, hashes)

	// 2. Build Tree B (Mutated)
	fmt.Println("Building Tree B...")
	hashes2 := make([]merkletree.Hash32, len(hashes))
	copy(hashes2, hashes)

	// Randomly pick an index to mutate
	mutateIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(count)))
	idx := int(mutateIdx.Int64())

	// Flip a byte
	hashes2[idx][0] ^= 0xFF

	fmt.Printf(">> Mutating Block #%d\n", idx)

	b2, _ := merkletree.NewBuilder(cfg)
	b2.Push(0, hashes2)

	b1.Visualize()
	b2.Visualize()

	// 3. Find Difference using Bisection
	fmt.Println("Running BisectDifference...")
	start, chunkCount, err := b1.Bisect(b2)
	if err != nil {
		t.Fatalf("Bisect error: %v", err)
	}

	fmt.Printf(">> Mismatch found at Chunk Range: [%d .. %d] (Count %d)\n", start, start+uint64(chunkCount)-1, chunkCount)

	// Verification
	// The mutated index `idx` should be within [start, start+count-1]
	if uint64(idx) >= start && uint64(idx) < start+uint64(chunkCount) {
		fmt.Println("SUCCESS: Mutated block is inside the identified chunk.")
	} else {
		t.Errorf("FAILURE: Mutated block %d NOT in range [%d .. %d]", idx, start, start+uint64(chunkCount)-1)
	}
}
