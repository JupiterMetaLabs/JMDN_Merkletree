package tests

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/neerajchowdary889/JMDN_Merkletree/merkletree"
)

func TestRandomizedDiff10k(t *testing.T) {
	count := 10000
	cfg := merkletree.Config{BlockMerge: 200}

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

	// 3. Find Difference
	fmt.Println("Running VisualizeDiff...")
	b1.Visualize(b2)
}
