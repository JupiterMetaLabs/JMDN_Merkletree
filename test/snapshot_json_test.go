package tests

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

func TestSnapshotFileAndBisect(t *testing.T) {
	// Scenario:
	// 1. Machine A: builds Tree A (Original).
	// 2. Machine A: saves Tree A to "tree_snapshot.json".
	// 3. Machine B: builds Tree B (Mutated).
	// 4. Machine B: loads Tree A from "tree_snapshot.json".
	// 5. Machine B: runs Bisect(A, B) to find the diff.

	count := 1000
	cfg := merkletree.Config{BlockMerge: 100}

	// ---- 1. Build Tree A (Original) ----
	fmt.Println("Building Tree A (Original)...")
	hashes := make([]merkletree.Hash32, count)
	for i := 0; i < count; i++ {
		rand.Read(hashes[i][:])
	}

	b1, _ := merkletree.NewBuilder(cfg)
	b1.Push(0, hashes)

	// ---- 2. Save to JSON File ----
	fmt.Println("Saving Tree A to 'tree_snapshot.json'...")
	snap := b1.ToSnapshot()
	jsonBytes, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	tmpFile := "tree_snapshot.json"
	// defer os.Remove(tmpFile) // clean up (Disabled so user can see it)
	if err := os.WriteFile(tmpFile, jsonBytes, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// ---- 3. Build Tree B (Mutated) ----
	fmt.Println("Building Tree B (Mutated)...")
	hashes2 := make([]merkletree.Hash32, len(hashes))
	copy(hashes2, hashes)

	// Mutate one block
	mutateIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(count)))
	idx := int(mutateIdx.Int64())
	hashes2[idx][0] ^= 0xFF
	fmt.Printf(">> Mutating Block #%d\n", idx)

	b2, _ := merkletree.NewBuilder(cfg)
	b2.Push(0, hashes2)

	// ---- 4. Load Tree A from JSON ----
	fmt.Println("Loading Tree A from JSON...")
	readBytes, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var loadedSnap merkletree.MerkleTreeSnapshot
	if err := json.Unmarshal(readBytes, &loadedSnap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	b1Restored, err := merkletree.FromSnapshot(&loadedSnap, nil)
	if err != nil {
		t.Fatalf("FromSnapshot failed: %v", err)
	}

	// ---- 5. Bisect ----
	fmt.Println("Running Bisect(RestoredA, MutatedB)...")

	// Verify roots first (should differ)
	r1, _ := b1Restored.Finalize()
	r2, _ := b2.Finalize()
	if r1 == r2 {
		t.Fatal("Roots should differ but match!")
	}

	start, bCount, err := b1Restored.Bisect(b2)
	if err != nil {
		t.Fatalf("Bisect failed: %v", err)
	}

	fmt.Printf(">> Difference found at range [%d .. %d]\n", start, start+uint64(bCount)-1)

	if uint64(idx) >= start && uint64(idx) < start+uint64(bCount) {
		fmt.Println("SUCCESS: Mutated index is within identified range.")
	} else {
		t.Fatalf("FAILURE: Mutated index %d NOT in range [%d .. %d]", idx, start, start+uint64(bCount)-1)
	}
}
