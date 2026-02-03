// Package syncmerkle implements a streaming, range-tagged “Merkle trie” builder
// for paginated block-hash pushes.
//
// Default behavior (fast path):
//   - “blockMerge” = 200 by default
//   - For each chunk of up to blockMerge block hashes, compute a DIRECT chunk digest
//     tagged with (startHeight, count). No inner Merkle by default.
//   - Build an OUTER streaming Merkle accumulator over chunk digests, also range-tagged.
//
// On-demand behavior (debug/repair):
//   - Compute a real Merkle root for a specific <=200 range only when needed.
//
// Design highlights:
//   - Bounded memory: O(log #chunks) + O(blockMerge) for partial chunk buffering.
//   - Deterministic: range metadata is committed into every hash.
//   - Supports snapshot/restore (for WAL persistence) by serializing peaks + partial chunk.
//
// Note: This is NOT an Ethereum MPT. It’s a 2-level authenticated structure over ordered heights.
package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

type Hash32 [32]byte

// ---- Domain tags (1 byte each) ----
//
// Tags separate layers and node types to avoid ambiguity / cross-layer collisions.
const (
	tagElem       = byte(0x21) // per-block element inside chunk digest: H(tagElem||height||blockHash)
	tagChunk      = byte(0x10) // chunk digest: H(tagChunk||start||count||elem1||...||elemK)
	tagOuterNode  = byte(0x11) // outer internal node: H(tagOuterNode||start||count||left||right)
	tagInnerLeaf  = byte(0x30) // on-demand inner merkle leaf: H(tagInnerLeaf||height||blockHash)
	tagInnerNode  = byte(0x31) // on-demand inner merkle node: H(tagInnerNode||start||count||left||right)
	tagChunkMerk  = byte(0x32) // optional wrapper: H(tagChunkMerk||start||count||innerRoot)
	tagSnapshotV1 = byte(0xA1) // snapshot format version
)

// HashFactory returns a new streaming hasher. Use SHA-256 by default.
type HashFactory func() hash.Hash

func DefaultHashFactory() hash.Hash { return sha256.New() }

type Config struct {
	BlockMerge  int
	HashFactory HashFactory
	// Optional: if set, Builder enforces contiguous heights starting at StartHeight.
	StartHeight *uint64
}

type Builder struct {
	cfg Config

	// expectedNextHeight is the next height Builder expects in Push (if StartHeight provided).
	expectedNextHeight uint64
	enforceHeights     bool

	// Partial chunk buffer (we store per-block element hashes so we can snapshot/restore).
	inChunkElems []Hash32 // length <= blockMerge
	inChunkStart uint64

	// Outer accumulator peaks.
	outer peaksAccumulator

	totalBlocks uint64
}

func NewBuilder(cfg Config) (*Builder, error) {
	if cfg.BlockMerge <= 0 {
		cfg.BlockMerge = 200
	}
	if cfg.HashFactory == nil {
		cfg.HashFactory = func() hash.Hash { return DefaultHashFactory() }
	}
	b := &Builder{
		cfg:          cfg,
		inChunkElems: make([]Hash32, 0, cfg.BlockMerge),
		outer:        newPeaksAccumulator(cfg.HashFactory, outerNodeDigest),
	}
	if cfg.StartHeight != nil {
		b.enforceHeights = true
		b.expectedNextHeight = *cfg.StartHeight
	}
	return b, nil
}

type State struct {
	TotalBlocks  uint64
	Committed    uint64 // number of full/partial chunks committed to outer so far
	InChunkCount int
	NextHeight   uint64 // meaningful if StartHeight enforced
}

func (b *Builder) State() State {
	return State{
		TotalBlocks:  b.totalBlocks,
		Committed:    b.outer.leafCount,
		InChunkCount: len(b.inChunkElems),
		NextHeight:   b.expectedNextHeight,
	}
}

// Push ingests a contiguous batch of block hashes.
// If cfg.StartHeight was provided, Push enforces that hashes correspond to consecutive heights.
//
// If you enforce heights, pass startHeight for this batch; otherwise pass anything (ignored).
func (b *Builder) Push(startHeight uint64, blockHashes []Hash32) (int, error) {
	if len(blockHashes) == 0 {
		return 0, nil
	}

	if b.enforceHeights {
		// Ensure the batch starts where we expect.
		if startHeight != b.expectedNextHeight {
			return 0, fmt.Errorf("unexpected startHeight: got %d want %d", startHeight, b.expectedNextHeight)
		}
	}

	accepted := 0
	for i := 0; i < len(blockHashes); i++ {
		h := blockHashes[i]

		var height uint64
		if b.enforceHeights {
			height = b.expectedNextHeight
		} else {
			// If not enforcing, we infer heights relative to this batch start and current partial.
			// For correctness across batches, prefer enforcing heights.
			height = startHeight + uint64(i)
		}

		// If starting a fresh chunk, lock in the chunk start height.
		if len(b.inChunkElems) == 0 {
			b.inChunkStart = height
		} else {
			// Contiguity inside a chunk is assumed; if enforcing, it's guaranteed.
			// If not enforcing, we do a best-effort check:
			expected := b.inChunkStart + uint64(len(b.inChunkElems))
			if height != expected {
				return accepted, fmt.Errorf("non-contiguous height inside chunk: got %d want %d", height, expected)
			}
		}

		// Compute per-block element hash with metadata binding (height).
		elem := elemDigest(b.cfg.HashFactory, height, h)
		b.inChunkElems = append(b.inChunkElems, elem)

		b.totalBlocks++
		accepted++

		if b.enforceHeights {
			b.expectedNextHeight++
		}

		// If chunk complete, commit it to the outer accumulator.
		if len(b.inChunkElems) == b.cfg.BlockMerge {
			if err := b.commitCurrentChunk(); err != nil {
				return accepted, err
			}
		}
	}

	return accepted, nil
}

// Finalize commits any partial chunk (if present) and returns the global root.
// If there were no leaves at all, returns the zero hash.
func (b *Builder) Finalize() (Hash32, error) {
	// Commit partial chunk if any.
	if len(b.inChunkElems) > 0 {
		if err := b.commitCurrentChunk(); err != nil {
			return Hash32{}, err
		}
	}
	return b.outer.Root(), nil
}

// Commit the current chunk (full or partial) into the outer accumulator, then reset in-chunk state.
func (b *Builder) commitCurrentChunk() error {
	if len(b.inChunkElems) == 0 {
		return nil
	}

	start := b.inChunkStart
	count := uint32(len(b.inChunkElems))

	// Direct chunk digest, tagged with range metadata.
	chunk := chunkDigest(b.cfg.HashFactory, start, count, b.inChunkElems)

	// Add to outer accumulator as a leaf node with explicit range.
	if err := b.outer.AddLeaf(node{
		start: start,
		count: count,
		sum:   chunk,
	}); err != nil {
		return err
	}

	// Reset partial chunk buffer.
	b.inChunkElems = b.inChunkElems[:0]
	b.inChunkStart = 0
	return nil
}

// Snapshot serializes builder state so you can persist it to your WAL.
func (b *Builder) Snapshot() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(tagSnapshotV1)

	// Config fields that affect hashing/determinism
	if err := writeU32(&buf, uint32(b.cfg.BlockMerge)); err != nil {
		return nil, err
	}
	// We do NOT serialize HashFactory; caller must restore with same config.

	// Height enforcement
	if b.enforceHeights {
		buf.WriteByte(1)
		if err := writeU64(&buf, b.expectedNextHeight); err != nil {
			return nil, err
		}
	} else {
		buf.WriteByte(0)
	}

	// Totals
	if err := writeU64(&buf, b.totalBlocks); err != nil {
		return nil, err
	}

	// Partial chunk
	if err := writeU64(&buf, b.inChunkStart); err != nil {
		return nil, err
	}
	if err := writeU32(&buf, uint32(len(b.inChunkElems))); err != nil {
		return nil, err
	}
	for _, e := range b.inChunkElems {
		buf.Write(e[:])
	}

	// Outer peaks
	if err := b.outer.Encode(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Restore loads a snapshot previously produced by Snapshot().
// Caller must create Builder with the same Config (blockMerge + hash function).
func (b *Builder) Restore(snapshot []byte) error {
	r := bytes.NewReader(snapshot)

	v, err := r.ReadByte()
	if err != nil {
		return err
	}
	if v != tagSnapshotV1 {
		return fmt.Errorf("unsupported snapshot version: %x", v)
	}

	blockMerge, err := readU32(r)
	if err != nil {
		return err
	}
	if int(blockMerge) != b.cfg.BlockMerge {
		return fmt.Errorf("snapshot blockMerge %d != builder blockMerge %d", blockMerge, b.cfg.BlockMerge)
	}

	enf, err := r.ReadByte()
	if err != nil {
		return err
	}
	if enf == 1 {
		b.enforceHeights = true
		b.expectedNextHeight, err = readU64(r)
		if err != nil {
			return err
		}
	} else {
		b.enforceHeights = false
	}

	b.totalBlocks, err = readU64(r)
	if err != nil {
		return err
	}

	// Partial chunk
	b.inChunkStart, err = readU64(r)
	if err != nil {
		return err
	}
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if int(n) > b.cfg.BlockMerge {
		return fmt.Errorf("snapshot inChunkCount %d > blockMerge %d", n, b.cfg.BlockMerge)
	}
	b.inChunkElems = make([]Hash32, 0, b.cfg.BlockMerge)
	for i := 0; i < int(n); i++ {
		var e Hash32
		if _, err := r.Read(e[:]); err != nil {
			return err
		}
		b.inChunkElems = append(b.inChunkElems, e)
	}

	// Outer peaks
	b.outer = newPeaksAccumulator(b.cfg.HashFactory, outerNodeDigest)
	if err := b.outer.Decode(r); err != nil {
		return err
	}

	return nil
}

// ------------------------------
// On-demand Merkle for <=200
// ------------------------------

// InnerMerkleForRange computes a true Merkle root for a specific range, for debug/repair.
// It binds each leaf to its height, and binds every internal node to (start,count).
//
// If you want a chunk-committable wrapper, set wrap=true to return
// H(tagChunkMerk || start || count || innerRoot).
func InnerMerkleForRange(hf HashFactory, startHeight uint64, blockHashes []Hash32, wrap bool) (Hash32, error) {
	if hf == nil {
		hf = func() hash.Hash { return DefaultHashFactory() }
	}
	if len(blockHashes) == 0 {
		return Hash32{}, nil
	}
	// Use an accumulator to avoid building a full tree in memory.
	acc := newPeaksAccumulator(hf, innerNodeDigest)

	for i, bh := range blockHashes {
		height := startHeight + uint64(i)
		leaf := innerLeafDigest(hf, height, bh)
		if err := acc.AddLeaf(node{
			start: height,
			count: 1,
			sum:   leaf,
		}); err != nil {
			return Hash32{}, err
		}
	}

	root := acc.Root()
	// Now bind the final root to the full range explicitly.
	if wrap {
		h := hf()
		h.Write([]byte{tagChunkMerk})
		writeU64ToHash(h, startHeight)
		writeU32ToHash(h, uint32(len(blockHashes)))
		h.Write(root[:])
		return sumTo32(h), nil
	}

	return root, nil
}

// ------------------------------
// Hashing primitives
// ------------------------------

func elemDigest(hf HashFactory, height uint64, blockHash Hash32) Hash32 {
	h := hf()
	h.Write([]byte{tagElem})
	writeU64ToHash(h, height)
	h.Write(blockHash[:])
	return sumTo32(h)
}

func chunkDigest(hf HashFactory, start uint64, count uint32, elems []Hash32) Hash32 {
	h := hf()
	h.Write([]byte{tagChunk})
	writeU64ToHash(h, start)
	writeU32ToHash(h, count)
	for _, e := range elems {
		h.Write(e[:])
	}
	return sumTo32(h)
}

func outerNodeDigest(hf HashFactory, start uint64, count uint32, left Hash32, right Hash32) Hash32 {
	h := hf()
	h.Write([]byte{tagOuterNode})
	writeU64ToHash(h, start)
	writeU32ToHash(h, count)
	h.Write(left[:])
	h.Write(right[:])
	return sumTo32(h)
}

func innerLeafDigest(hf HashFactory, height uint64, blockHash Hash32) Hash32 {
	h := hf()
	h.Write([]byte{tagInnerLeaf})
	writeU64ToHash(h, height)
	h.Write(blockHash[:])
	return sumTo32(h)
}

func innerNodeDigest(hf HashFactory, start uint64, count uint32, left Hash32, right Hash32) Hash32 {
	h := hf()
	h.Write([]byte{tagInnerNode})
	writeU64ToHash(h, start)
	writeU32ToHash(h, count)
	h.Write(left[:])
	h.Write(right[:])
	return sumTo32(h)
}

// ComputeChunkDigest calculates the chunk digest for a specific set of blocks
// effectively replicating the "fast path" without creating a full Builder.
// It matches the internal behavior of Builder for a single chunk.
func ComputeChunkDigest(hf HashFactory, startHeight uint64, blockHashes []Hash32) Hash32 {
	if hf == nil {
		hf = func() hash.Hash { return DefaultHashFactory() }
	}
	count := uint32(len(blockHashes))
	if count == 0 {
		return Hash32{}
	}

	elems := make([]Hash32, count)
	for i, h := range blockHashes {
		elems[i] = elemDigest(hf, startHeight+uint64(i), h)
	}
	return chunkDigest(hf, startHeight, count, elems)
}

func sumTo32(h hash.Hash) Hash32 {
	sum := h.Sum(nil)
	var out Hash32
	copy(out[:], sum[:32])
	return out
}

// ------------------------------
// Peaks accumulator (streaming Merkle)
// ------------------------------

type node struct {
	start uint64
	count uint32
	sum   Hash32
}

type nodeCombiner func(hf HashFactory, start uint64, count uint32, left Hash32, right Hash32) Hash32

type peaksAccumulator struct {
	hf        HashFactory
	combiner  nodeCombiner
	peaks     []*node
	leafCount uint64 // number of leaves added
}

func newPeaksAccumulator(hf HashFactory, combiner nodeCombiner) peaksAccumulator {
	return peaksAccumulator{hf: hf, combiner: combiner}
}

func (a *peaksAccumulator) AddLeaf(n node) error {
	// Enforce contiguity when combining: left range must end exactly before right begins.
	carry := &n
	level := 0

	for {
		// Extend peaks slice if needed.
		if level >= len(a.peaks) {
			a.peaks = append(a.peaks, nil)
		}
		if a.peaks[level] == nil {
			a.peaks[level] = carry
			a.leafCount++
			return nil
		}

		left := a.peaks[level]
		right := carry

		// Contiguity check: left.start + left.count == right.start
		if left.start+uint64(left.count) != right.start {
			return fmt.Errorf("non-contiguous combine at level %d: left [%d..%d] right [%d..%d]",
				level,
				left.start, left.start+uint64(left.count)-1,
				right.start, right.start+uint64(right.count)-1,
			)
		}

		combinedStart := left.start
		combinedCount := left.count + right.count
		combinedSum := a.combiner(a.hf, combinedStart, combinedCount, left.sum, right.sum)

		// Clear this peak and carry to next level.
		a.peaks[level] = nil
		carry = &node{start: combinedStart, count: combinedCount, sum: combinedSum}
		level++
	}
}

func (a *peaksAccumulator) Root() Hash32 {
	// Fold remaining peaks left-to-right.
	// Peaks are stored by level, but because we add sequentially,
	// higher levels contain "older" (left-side) ranges.
	// To reconstruct the tree order, we must process from largest level (oldest) to smallest.
	var root *node
	for i := len(a.peaks) - 1; i >= 0; i-- {
		p := a.peaks[i]
		if p == nil {
			continue
		}
		if root == nil {
			// copy
			tmp := *p
			root = &tmp
			continue
		}
		// Combine root (left) with p (right) ensuring contiguity.
		if root.start+uint64(root.count) != p.start {
			// If this happens, inputs weren’t contiguous or caller mixed ranges.
			// Return zero to avoid false confidence.
			return Hash32{}
		}
		root = &node{
			start: root.start,
			count: root.count + p.count,
			sum:   a.combiner(a.hf, root.start, root.count+p.count, root.sum, p.sum),
		}
	}
	if root == nil {
		return Hash32{}
	}
	return root.sum
}

// Encode serializes peaks and leafCount.
func (a *peaksAccumulator) Encode(buf *bytes.Buffer) error {
	if err := writeU64(buf, a.leafCount); err != nil {
		return err
	}
	if err := writeU32(buf, uint32(len(a.peaks))); err != nil {
		return err
	}
	for _, p := range a.peaks {
		if p == nil {
			buf.WriteByte(0)
			continue
		}
		buf.WriteByte(1)
		if err := writeU64(buf, p.start); err != nil {
			return err
		}
		if err := writeU32(buf, p.count); err != nil {
			return err
		}
		buf.Write(p.sum[:])
	}
	return nil
}

func (a *peaksAccumulator) Decode(r *bytes.Reader) error {
	lc, err := readU64(r)
	if err != nil {
		return err
	}
	a.leafCount = lc

	n, err := readU32(r)
	if err != nil {
		return err
	}

	a.peaks = make([]*node, int(n))
	for i := 0; i < int(n); i++ {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if b == 0 {
			a.peaks[i] = nil
			continue
		}
		start, err := readU64(r)
		if err != nil {
			return err
		}
		count, err := readU32(r)
		if err != nil {
			return err
		}
		var s Hash32
		if _, err := r.Read(s[:]); err != nil {
			return err
		}
		a.peaks[i] = &node{start: start, count: count, sum: s}
	}
	return nil
}

// ------------------------------
// Binary encoding helpers
// ------------------------------

func writeU64(buf *bytes.Buffer, v uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	_, err := buf.Write(b[:])
	return err
}

func writeU32(buf *bytes.Buffer, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	_, err := buf.Write(b[:])
	return err
}

func readU64(r *bytes.Reader) (uint64, error) {
	var b [8]byte
	if _, err := r.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func readU32(r *bytes.Reader) (uint32, error) {
	var b [4]byte
	if _, err := r.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func writeU64ToHash(h hash.Hash, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	h.Write(b[:])
}

func writeU32ToHash(h hash.Hash, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	h.Write(b[:])
}

// ------------------------------
// Convenience: sanity checks
// ------------------------------

var (
	ErrConfigMismatch = errors.New("config mismatch")
)

// EnsureSameRoot is a tiny helper for comparing roots.
func EnsureSameRoot(a, b Hash32) error {
	if a != b {
		return errors.New("roots differ")
	}
	return nil
}
