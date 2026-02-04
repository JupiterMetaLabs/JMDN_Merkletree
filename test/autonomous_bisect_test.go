package tests

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

func TestAutonomousBisection(t *testing.T) {
	// 1. Setup: Create a "Remote" tree (Ground Truth)
	count := 10000
	cfg := merkletree.Config{BlockMerge: 100} // Force small chunks for deeper tree
	remoteData := make([]merkletree.Hash32, count)
	for i := 0; i < count; i++ {
		rand.Read(remoteData[i][:])
	}

	remoteBuilder, _ := merkletree.NewBuilder(cfg)
	remoteBuilder.Push(0, remoteData)

	// 2. Snapshot "Remote" (Full Serialization)
	snapshot, err := remoteBuilder.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	fmt.Printf("Snapshot Size: %d bytes\n", len(snapshot))

	// 3. Setup: Create "Local" tree with ONE mismatch
	localBuilder, _ := merkletree.NewBuilder(cfg)
	localData := make([]merkletree.Hash32, count)
	copy(localData, remoteData)

	// Mutate block 5050
	mismatchIndex := 5050
	rand.Read(localData[mismatchIndex][:]) // Change hash
	localBuilder.Push(0, localData)

	// 4. Restore "Remote" from snapshot -> "RestoredRemote"
	// This simulates a receiver having ONLY the snapshot, no raw data.
	restoredRemote, _ := merkletree.NewBuilder(cfg)
	if err := restoredRemote.Restore(snapshot); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// 5. Run Bisection
	// Local vs RestoredRemote
	// If the snapshot contains the full tree, this should work perfectly.
	fmt.Println("Running Autonomous Bisection...")
	start, bCount, err := localBuilder.Bisect(restoredRemote)
	if err != nil {
		t.Fatalf("Bisect failed: %v", err)
	}

	fmt.Printf("Mismatch identified at range [%d .. %d] (size %d)\n", start, start+uint64(bCount)-1, bCount)

	// 6. Verify
	// Chunk size is 100 (BlockMerge).
	// 5050 should be in range [5000 .. 5099].
	if uint64(mismatchIndex) >= start && uint64(mismatchIndex) < start+uint64(bCount) {
		fmt.Println("SUCCESS: Mismatch correctly identified.")
	} else {
		t.Fatalf("FAILURE: Mismatch index %d NOT in range [%d .. %d]", mismatchIndex, start, start+uint64(bCount))
	}
}
