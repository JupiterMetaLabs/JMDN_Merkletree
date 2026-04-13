# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
go test -v ./test

# Run a single test
go test -v ./test -run TestName

# Build (library only, no binary)
go build ./...
```

## Architecture

**JMDN_Merkletree** is a Go library implementing an ordered streaming Merkle tree for efficient keyspace diffing in distributed systems (e.g., blockchain sync). Module: `github.com/JupiterMetaLabs/JMDN_Merkletree`.

### Two-Level Tree Design

The tree has two layers:

1. **Inner layer (chunks):** Block hashes are grouped into fixed-size chunks (`BlockMerge`, default derived from `ExpectedTotal`). Each chunk produces a digest using XOR of domain-tagged per-block hashes plus range metadata (startHeight, count).

2. **Outer layer (accumulator):** A streaming Merkle Mountain Range (MMR) over chunk digests. Peaks are combined as more chunks arrive. Memory usage is O(log #chunks) + O(blockMerge).

Every hash at every level includes range metadata `(startHeight, count)` to prevent cross-tree hash collisions.

### Key Files

- **`merkletree/merkletree.go`** — Core `Builder` struct, `Config`, `Node`, `Push()`, `Finalize()`, `RootNode()`, binary snapshot/restore, JSON serialization.
- **`merkletree/bisection.go`** — `Bisect(other)`: finds the first differing chunk in O(log N) by traversing the outer MMR.
- **`merkletree/tree_bisection.go`** — `TreeBisect(other)`: compares whole trees including trees with different peak structures.
- **`merkletree/diff.go`** — `TreeDiff(other)`: returns all `[]DiffRange` between two trees.
- **`merkletree/multi_bisection.go`** — `MultiBisect(other, concurrency)`: parallel version of TreeDiff using goroutines with semaphore-based limiting.
- **`merkletree/snapshot_types.go`** — JSON-serializable types: `MerkleTreeSnapshot`, `SnapshotNode`, `SnapshotConfig`.
- **`merkletree/visulaize.go`** — `Visualize()`: debug print of partial chunk buffer and MMR peaks.

### Domain Tags

Single-byte prefixes used in all hash computations to prevent ambiguity:

| Tag | Hex | Used for |
|-----|-----|----------|
| `tagElem` | `0x21` | Per-block element within a chunk |
| `tagChunk` | `0x10` | Chunk digest (XOR of elements) |
| `tagOuterNode` | `0x11` | Outer MMR internal node |
| `tagInnerLeaf` | `0x30` | On-demand inner Merkle leaf |
| `tagInnerNode` | `0x31` | On-demand inner Merkle internal node |
| `tagChunkMerk` | `0x32` | Chunk wrapper for on-demand inner Merkle |
| `tagSnapshotV1` | `0xA1` | Binary snapshot format |

### Hashing

Default is SHA-256. Pluggable via `Config.HashFactory` interface. All hash functions receive domain-tagged, range-bound input.

### Serialization

Two formats exist:
- **Binary** (`Snapshot()` / `Restore()`): for WAL/recovery
- **JSON** (`ToSnapshot()` / `FromSnapshot()` / `SavetoJson()` / `LoadSnapshotfromJson()`): for transport/storage

### Tests

All tests live in `test/`. Test data files (`tree_snapshot.json`, `payload.json`) are committed and used as golden fixtures.
