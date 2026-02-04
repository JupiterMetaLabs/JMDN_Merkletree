package tests

import (
	"testing"
	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

func TestBasicFlow(t *testing.T) {
	cfg := merkletree.Config{
		BlockMerge: 4,
	}
	b, err := merkletree.NewBuilder(cfg)
	if err != nil {
		t.Fatalf("NewBuilder unexpected error: %v", err)
	}

	var hashes []merkletree.Hash32
	for i := 0; i < 10; i++ {
		var h merkletree.Hash32
		h[0] = byte(i)
		hashes = append(hashes, h)
	}

	// 1. Push 3
	n, err := b.Push(0, hashes[:3])
	if err != nil {
		t.Fatalf("Push 1 failed: %v", err)
	}
	if n != 3 {
		t.Errorf("Expected 3 accepted, got %d", n)
	}

	st := b.State()
	if st.TotalBlocks != 3 {
		t.Errorf("TotalBlocks 3 != %d", st.TotalBlocks)
	}

	// 2. Push 2 more (completes 4, adds 1)
	// Note: previous push was 3 items. Next height relative to block index if not enforced?
	// The implementation says: "If not enforcing... height = startHeight + uint64(i)".
	// We passed startHeight=0 for first generic push.
	// For second push, if we pass 0, the builder calculates:
	//   i=0 -> height=0.
	//   Builder checks: "expected := b.inChunkStart + len".
	//   Current inChunkStart=0 (from first push). len=3. Expected next=3.
	//   But we pass startHeight=0, so calculated height=0.
	//   0 != 3 => Error!
	// Ah, THAT IS WHY BasicFlow failed implicitly or likely returned error I missed?
	// "return accepted, fmt.Errorf..."
	// Wait, I checked "if err != nil".
	// Let's see.
	// "if height != expected { return accepted, error }"
	// So my second push failed.

	// FIX: Must pass correct startHeight even if not strictly enforced,
	// because Builder enforces *internal* consistency within a chunk.

	n, err = b.Push(3, hashes[3:5]) // start at index 3
	if err != nil {
		t.Fatalf("Push 2 failed: %v", err)
	}
	if n != 2 {
		t.Errorf("Expected 2 accepted, got %d", n)
	}

	st = b.State()
	if st.TotalBlocks != 5 {
		t.Errorf("TotalBlocks 5 != %d", st.TotalBlocks)
	}
	if st.Committed != 1 {
		t.Errorf("Committed chunks should be 1, got %d", st.Committed)
	}

	// Finalize
	root, err := b.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
	t.Logf("Global Root: %x", root)
}

func TestHeightEnforcement(t *testing.T) {
	start := uint64(100)
	cfg := merkletree.Config{
		BlockMerge:  4,
		StartHeight: &start,
	}
	b, err := merkletree.NewBuilder(cfg)
	if err != nil {
		t.Fatalf("NewBuilder failed: %v", err)
	}

	var h merkletree.Hash32
	_, err = b.Push(100, []merkletree.Hash32{h})
	if err != nil {
		t.Errorf("Valid push passed? %v", err)
	}

	_, err = b.Push(105, []merkletree.Hash32{h})
	if err == nil {
		t.Error("Expected error for non-contiguous push, got none")
	} else {
		t.Logf("Got expected error: %v", err)
	}
}

func TestOnDemandMatchesChunk_Determinism(t *testing.T) {
	hf := merkletree.DefaultHashFactory
	var hashes []merkletree.Hash32
	for i := 0; i < 5; i++ {
		var h merkletree.Hash32
		h[0] = byte(i)
		hashes = append(hashes, h)
	}

	root1, err := merkletree.InnerMerkleForRange(hf, 100, hashes, false)
	if err != nil {
		t.Fatalf("InnerMerkleForRange(100) failed: %v", err)
	}

	root2, err := merkletree.InnerMerkleForRange(hf, 100, hashes, false)
	if err != nil {
		t.Fatalf("InnerMerkleForRange(100) retry failed: %v", err)
	}

	if root1 != root2 {
		t.Error("InnerMerkleForRange non-deterministic")
	}

	// Change start height
	root3, err :=merkletree.InnerMerkleForRange(hf, 101, hashes, false)
	if err != nil {
		t.Fatalf("InnerMerkleForRange(101) failed: %v", err)
	}

	if root1 == root3 {
		t.Error("Metadata (startHeight) not affecting hash!")
	}
}

func TestAccumulatorMultipleChunks(t *testing.T) {
	cfg := merkletree.Config{BlockMerge: 2}
	b, _ := merkletree.NewBuilder(cfg)

	// Batch push
	// Heights: 0, 1, 2, 3
	hashes := make([]merkletree.Hash32, 4)
	for i := range hashes {
		hashes[i][0] = byte(i)
	}
	// Note: Push(0, ...) works because 0 is start.
	// Internal checks:
	// i=0, h=0. OK.
	// i=1, h=1. OK.
	// i=2, h=2. OK.
	// i=3, h=3. OK.
	b.Push(0, hashes)

	rootBatch, err := b.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Root batch: %x", rootBatch)

	// Stream push with enforcement to be safe/clear
	start := uint64(0)
	bStream, _ := merkletree.NewBuilder(merkletree.Config{BlockMerge: 2, StartHeight: &start})
	for i := 0; i < 4; i++ {
		// MUST pass correct height
		_, err := bStream.Push(uint64(i), hashes[i:i+1])
		if err != nil {
			t.Fatalf("Stream Push(%d) failed: %v", i, err)
		}
	}
	rootStream, _ := bStream.Finalize()

	if rootBatch != rootStream {
		t.Errorf("Streaming mismatch.\nBatch: %x\nStream: %x", rootBatch, rootStream)
	}
}

func TestSnapshotRestore(t *testing.T) {
	cfg := merkletree.Config{BlockMerge: 5}
	b1, _ := merkletree.NewBuilder(cfg)

	var hashes []merkletree.Hash32
	for i := 0; i < 7; i++ {
		var h merkletree.Hash32
		h[0] = byte(i)
		hashes = append(hashes, h)
	}
	// Push 0..6
	b1.Push(0, hashes)

	snap, err := b1.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	b2, _ := merkletree.NewBuilder(cfg)
	if err := b2.Restore(snap); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	st1 := b1.State()
	st2 := b2.State()
	if st1 != st2 {
		t.Errorf("States differ after restore.\nB1: %+v\nB2: %+v", st1, st2)
	}

	r1, _ := b1.Finalize()
	r2, _ := b2.Finalize()
	if r1 != r2 {
		t.Errorf("Roots differ after restore.\nR1: %x\nR2: %x", r1, r2)
	}
}

// Check that metadata is actually used (sanity check)
func TestMetadataSanity(t *testing.T) {
	// 1. Chunk with start=0
	b1, _ := merkletree.NewBuilder(merkletree.Config{BlockMerge: 10})
	b1.Push(0, []merkletree.Hash32{{1}})
	r1, _ := b1.Finalize()

	// 2. Chunk with start=100
	b2, _ := merkletree.NewBuilder(merkletree.Config{BlockMerge: 10})
	// Just passing 100 to Push without EnforceHeights uses 100 as base for that batch.
	b2.Push(100, []merkletree.Hash32{{1}})
	r2, _ := b2.Finalize()

	if r1 == r2 {
		t.Fatal("Root hash should differ when start height differs")
	}
}
