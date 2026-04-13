# JMDN_Merkletree

An ordered Merkle tree implementation designed for efficient keyspace diffing and partial resynchronization (e.g. blockchain sync). Module: `github.com/JupiterMetaLabs/JMDN_Merkletree`.

## Commands

```bash
# Run all Merkle tree tests
go test -v ./test

# Run a single test
go test -v ./test -run TestName

# Build (library)
go build ./...
```

Core tree code lives under `merkletree/` (`Builder`, `Push`, `Finalize`, bisection, diff, JSON/binary snapshots). See `CLAUDE.md` in the repo for file map, domain tags, and hashing details.

---

## DID Index benchmark

The repository includes optional **DID nonce index** implementations under `DIDIndex/` (ART, B+ tree, LSM, Roaring bitmap, finger tree, fractal tree, and a **Hybrid** Roaring + B+ tree). They share the `DIDIndex` interface (`Insert`, `Contains`, `Merge`, `Iter`, etc.).

A unified comparison table is printed by:

```bash
go test -v -run TestFullReport ./DIDIndex/bench/
```

Micro-benchmarks use a different harness:

```bash
go test -bench=. -benchmem -benchtime=3s ./DIDIndex/bench/
```

### Workload

| Parameter | Value |
|-----------|--------|
| **n** | `10_000` keys (`benchN` in `DIDIndex/bench/bench_test.go`) |
| **Key pattern** | **Sequential nanosecond-style nonces**: high 48 bits are timestamps starting at `baseTS`, stepped by **1 µs** (`+1000` ns) per key; low 16 bits are **random** (`seed=42` for the main bulk, different seeds for merge halves). |
| **Rationale** | Matches a DID-style `uint64` nonce: coarse time in the high bits, suffix in the low bits. Sequential timestamps favor **bitmap-heavy** structures (Roaring, Hybrid) for dense windows. |

Algorithms under test: **ART**, **B+Tree**, **LSM**, **Roaring**, **FingerTree**, **FractalTree**, **Hybrid[REC]** (see `allImpls()` in `bench_test.go`).

### Timing methodology

For each algorithm, the test:

1. Builds an index with all `n` nonces and measures **heap delta** (`runtime.MemStats` after `GC`).
2. Runs **warmup** iterations (`warmup = 3`) then **timed** repetitions (`reps = 20`) for Insert, Contains, Merge, and Decompress sections.
3. Reports **averages** over `reps` (Insert/Merge/Decompress per full operation; Contains as **per lookup** over `n` probes).

Absolute numbers depend on CPU, OS, and Go version; **relative** ordering is usually more stable than raw microseconds.

### Column reference

The printed table has three groups: **Speed**, **Storage**, and **Compression**.

#### Speed

| Column | Meaning |
|--------|---------|
| **Insert (seq/op)** | Wall time to **build a fresh index** by inserting all `n` sequential nonces, averaged over repetitions. One “op” = full build. |
| **Contains (ns/key)** | Average time for **one successful** `Contains` call on keys present in the index (hit path). Each repetition runs `n` lookups. |
| **Merge (op)** | Wall time for: build index A with `n/2` nonces, build B with `n/2` nonces (disjoint streams), then **`A.Merge(B)`**, averaged over repetitions. |
| **Decompress +Unmarshal** | Full **sync-restore style** path: `gzip` decompress a payload that was compressed with **BestSpeed** from the **flat** marshalled bytes, then **`Unmarshal`** into a new empty index. Measures wire restore, not native compact format. |

#### Storage

| Column | Meaning |
|--------|---------|
| **HeapAlloc (RAM)** | Approximate **in-memory** footprint delta after inserting all `n` keys: `HeapAlloc` after minus before, with `GC` before/after (see test). |
| **Flat wire (8B/key)** | Size of **`didindex.Marshal(idx)`**: sorted **`uint64`** stream, **8 bytes per key** for every algorithm (~`n × 8` plus framing if any). Common baseline on the wire. |
| **Native (compact\*)** | **Algorithm-specific** compact serialization when implemented (`NativeMarshal()` on Roaring and Hybrid). The printed table appends **`◀`** when this column is the compact path (smaller than flat). Other algorithms use the same bytes as **Flat wire** here. |
| **Gzip(nat) (BestCmpr)** | Size after **`gzip.BestCompression`** on the **native** byte slice (or flat, when native = flat). |

#### Compression ratios

| Column | Meaning |
|--------|---------|
| **Flat→Gzip** | `100 × gzip_best(flat) / len(flat)` — how much gzip shrinks the **flat uint64** stream. |
| **Nat→Gzip** | `100 × gzip_best(native) / len(native)` — how much gzip shrinks the **native** payload. For Roaring/Hybrid, native is already dense, so this ratio is often **near 100%** (little extra gain from gzip). |

### Reading the results

- **Roaring** and **Hybrid[REC]** typically show **much smaller Native** than Flat for sequential dense ranges, because many keys collapse into **bitmap containers** instead of storing every `uint64` literally.
- **Insert** cost includes tree/bitmap maintenance; **Contains (hit)** is usually dominated by a short search plus bitmap/array probe.
- **Merge** can use **structure-aware** unions (e.g. container OR) for Roaring/Hybrid when merging another instance of the same type; other paths fall back to iterating and inserting.
- **Decompress** timings reflect **flat** format restore; if production uses **native** frames, add a separate benchmark or extend the test for that path.

### Example row (illustrative)

For `n = 10_000` sequential nonces, a single run might look like the following (numbers vary by machine):

| Algorithm | Insert | Contains | Merge | Decompress | HeapAlloc | Native |
|-----------|--------|----------|-------|------------|-----------|--------|
| Roaring | ~203 µs | ~28 ns | ~246 µs | ~405 µs | ~48 KB | ~20.87 KB ◀ |
| Hybrid[REC] | ~305 µs | ~33 ns | ~358 µs | ~433 µs | ~47 KB | ~20.28 KB ◀ |

Treat these as **samples**, not guarantees.

### Related code

- `DIDIndex/index.go` — `DIDIndex` interface.
- `DIDIndex/bench/bench_test.go` — `TestFullReport`, `printReport`, nonce generators, `metrics`.
- Implementations: `DIDIndex/roaring`, `DIDIndex/hybrid`, `DIDIndex/bptree`, etc.

The test also prints short footnotes after the table (Insert / Contains / Merge / Decompress / Flat / Native / Gzip definitions); those match the descriptions above.
