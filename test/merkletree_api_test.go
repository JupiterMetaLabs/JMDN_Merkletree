package tests

import (
	"testing"

	"github.com/neerajchowdary889/JMDN_Merkletree/merkletree"
)

func TestComputeChunkDigest(t *testing.T) {
	// Create some dummy block hashes
	hashes := make([]merkletree.Hash32, 5)
	for i := range hashes {
		hashes[i][0] = byte(i + 1)
	}
	startHeight := uint64(100)

	// 1. Compute via standalone helper
	digestDirect := merkletree.ComputeChunkDigest(nil, startHeight, hashes)

	// 2. Compute via Builder (the "canonical" way)
	cfg := merkletree.Config{
		BlockMerge:  len(hashes),
		StartHeight: &startHeight,
	}
	b, err := merkletree.NewBuilder(cfg)
	if err != nil {
		t.Fatalf("NewBuilder failed: %v", err)
	}
	_, err = b.Push(startHeight, hashes)
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	// But wait, Builder produces a "Global Root".
	// For a single chunk, the "Global Root" is:
	//   LeafNode(ChunkDigest) -> Root.
	// We want to verify the *ChunkDigest* itself.
	// The Builder doesn't expose the ChunkDigest directly unless we inspect internals or
	// verify that Finalize() -> OuterRoot(ChunkDigest) is what we expect.

	// Let's manually build what the global root SHOULD be if the chunk digest is correct.
	// GlobalRoot = OuterNodeDigest(start, count, Leaf=ChunkDigest) ??
	// No, Finalize() iterates peaks.
	// If only 1 chunk, peaks[0] is that chunk node.
	// Node is {start, count, sum=ChunkDigest}.
	// So Finalize() returns... Node.sum? No.
	// Wait, peaksAccumulator.Root():
	// If one peak, it returns peak.sum.
	// "peak.sum" IS the ChunkDigest?
	// Let's check AddLeaf in Builder.
	// b.outer.AddLeaf(node{ start, count, sum: chunk })
	// So YES, if there is exactly one full chunk, the Root() of the accumulator is that one leaf's sum,
	// which is the chunk digest itself (because peaksAccumulator doesn't wrap a single leaf in another outer node unless combining).

	// Let's verify this assumption by looking at peaksAccumulator.Root() logic.
	// "for i := len(peaks)-1 ... combine".
	// If only 1 peak, "root = &tmp", then return root.sum.
	// So YES, for a single chunk that fits exactly in BlockMerge, Finalize() == ChunkDigest.

	digestBuilder, err := b.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	if digestDirect != digestBuilder {
		t.Errorf("Mismatch!\nDirect:  %x\nBuilder: %x", digestDirect, digestBuilder)
	}
}

func TestInnerMerkleAPI(t *testing.T) {
	// Verify InnerMerkleForRange works and returns deterministic results (already checked in other test, but good to have explicit API test)
	hashes := make([]merkletree.Hash32, 3)
	for i := range hashes {
		hashes[i][0] = byte(0xAA)
	}

	// 1. Raw root
	root, err := merkletree.InnerMerkleForRange(nil, 50, hashes, false)
	if err != nil {
		t.Fatalf("InnerMerkleForRange failed: %v", err)
	}
	if root == (merkletree.Hash32{}) {
		t.Error("Got zero hash for valid input")
	}

	// 2. Wrapped
	wrapped, err := merkletree.InnerMerkleForRange(nil, 50, hashes, true)
	if err != nil {
		t.Fatalf("Wrapped failed: %v", err)
	}
	if wrapped == root {
		t.Error("Wrapped hash should differ from raw root")
	}
}
