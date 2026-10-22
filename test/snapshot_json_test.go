package tests

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

func TestSnapshotFileAndDiff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tree_snapshot.json")

	// Scenario:
	// 1. Machine A: builds Tree A (Original).
	// 2. Machine A: saves Tree A to "tree_snapshot.json".
	// 3. Machine B: builds Tree B (Mutated).
	// 4. Machine B: loads Tree A from "tree_snapshot.json".
	// 5. Machine B: runs TreeDiff(A, B) to find the diff.

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
		t.Fatalf("encode snapshot failed: %v", err)
	}
	if err := os.WriteFile(path, jsonBytes, 0o644); err != nil {
		t.Fatalf("write snapshot failed: %v", err)
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
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot failed: %v", err)
	}
	loadedSnap := &merkletree.MerkleTreeSnapshot{}
	if err := json.Unmarshal(raw, loadedSnap); err != nil {
		t.Fatalf("decode snapshot failed: %v", err)
	}

	b1Restored, err := loadedSnap.FromSnapshot(nil)
	if err != nil {
		t.Fatalf("FromSnapshot failed: %v", err)
	}

	// ---- 5. Diff ----
	fmt.Println("Running TreeDiff(RestoredA, MutatedB)...")

	// Verify roots first (should differ)
	r1, _ := b1Restored.Finalize()
	r2, _ := b2.Finalize()
	if r1 == r2 {
		t.Fatal("Roots should differ but match!")
	}

	diffs, err := b1Restored.TreeDiff(b2)
	if err != nil {
		t.Fatalf("TreeDiff failed: %v", err)
	}
	if !rangesContain(diffs, uint64(idx)) {
		t.Fatalf("FAILURE: Mutated index %d not in any diff range %+v", idx, diffs)
	}
}

// rangesContain reports whether height falls inside any of the diff ranges.
func rangesContain(diffs []merkletree.DiffRange, height uint64) bool {
	for _, d := range diffs {
		if height >= d.Start && height < d.Start+uint64(d.Count) {
			return true
		}
	}
	return false
}
