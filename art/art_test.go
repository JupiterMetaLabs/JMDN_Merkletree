package art

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// ─── nonce data (loaded once by TestMain) ─────────────────────────────────────

var allNonces []uint64

func TestMain(m *testing.M) {
	path := filepath.Join("..", "data", "nonce.jsonl")
	var err error
	allNonces, err = loadNonces(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: could not load %s (%v) — report test will skip\n", path, err)
	}
	os.Exit(m.Run())
}

func loadNonces(path string) ([]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type entry struct {
		Nonce uint64 `json:"nonce"`
	}

	br := bufio.NewReaderSize(f, 8<<20) // 8 MB read buffer
	dec := json.NewDecoder(br)
	out := make([]uint64, 0, 3_000_000)
	var e entry
	for dec.More() {
		e.Nonce = 0
		if err := dec.Decode(&e); err != nil {
			continue
		}
		out = append(out, e.Nonce)
	}
	return out, nil
}

// ─── ART unit tests ───────────────────────────────────────────────────────────

func TestInsertContains(t *testing.T) {
	a := New()
	keys := []uint64{0, 1, 255, 1 << 16, 1<<32 - 1, 1<<63 + 42, ^uint64(0)}
	for _, k := range keys {
		a.Insert(k)
	}
	for _, k := range keys {
		if !a.Contains(k) {
			t.Errorf("Contains(%d) = false, want true", k)
		}
	}
	if a.Len() != len(keys) {
		t.Errorf("Len() = %d, want %d", a.Len(), len(keys))
	}
	if a.Contains(99999999) {
		t.Errorf("Contains(99999999) = true for absent key")
	}
}

func TestDelete(t *testing.T) {
	a := New()
	for i := range 100 {
		a.Insert(uint64(i))
	}
	for i := range 100 {
		if i%2 == 0 {
			if !a.Delete(uint64(i)) {
				t.Errorf("Delete(%d) = false, want true", i)
			}
		}
	}
	if a.Len() != 50 {
		t.Errorf("Len() after deletes = %d, want 50", a.Len())
	}
	for i := range 100 {
		want := i%2 != 0
		if a.Contains(uint64(i)) != want {
			t.Errorf("Contains(%d) = %v, want %v", i, !want, want)
		}
	}
	if a.Delete(0) {
		t.Errorf("Delete(0) = true for absent key")
	}
}

func TestMerge(t *testing.T) {
	a, b := New(), New()
	for i := range 50 {
		a.Insert(uint64(i))
	}
	for i := 25; i < 75; i++ {
		b.Insert(uint64(i))
	}
	a.Merge(b)
	if a.Len() != 75 {
		t.Errorf("Len() after merge = %d, want 75", a.Len())
	}
	for i := range 75 {
		if !a.Contains(uint64(i)) {
			t.Errorf("Contains(%d) = false after merge", i)
		}
	}
}

func TestIter(t *testing.T) {
	a := New()
	for i := range 10 {
		a.Insert(uint64(i * 10))
	}
	var got []uint64
	a.Iter(func(k uint64) { got = append(got, k) })
	if len(got) != 10 {
		t.Fatalf("Iter yielded %d keys, want 10", len(got))
	}
	for i, v := range got {
		if v != uint64(i*10) {
			t.Errorf("got[%d] = %d, want %d", i, v, i*10)
		}
	}
}

func TestEncodeDecodeWire(t *testing.T) {
	a := New()
	for i := range 1000 {
		a.Insert(uint64(i*7 + 13))
	}
	payload := Encode(a)
	if len(payload) == 0 {
		t.Fatal("Encode returned empty payload")
	}
	b, err := Decode(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if a.Len() != b.Len() {
		t.Errorf("Len mismatch: sender=%d receiver=%d", a.Len(), b.Len())
	}
	a.Iter(func(k uint64) {
		if !b.Contains(k) {
			t.Errorf("key %d missing after Decode", k)
		}
	})
	t.Logf("1000 keys: raw=%d B  encoded=%d B  ratio=%.1f%%",
		1000*8, len(payload), 100*float64(len(payload))/(1000*8))
}

// ─── SwappableART unit tests ──────────────────────────────────────────────────

func TestSwappableInsertContains(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSwappable(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := range 250 {
		if err := s.Insert(uint64(i)); err != nil {
			t.Fatalf("Insert(%d): %v", i, err)
		}
	}
	if s.SegmentCount() < 2 {
		t.Errorf("expected ≥2 segments after 250 inserts with threshold=100, got %d", s.SegmentCount())
	}
	for i := range 250 {
		if !s.Contains(uint64(i)) {
			t.Errorf("Contains(%d) = false", i)
		}
	}
	if s.Contains(9999) {
		t.Errorf("Contains(9999) = true for absent key")
	}
}

func TestSwappableDelete(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewSwappable(dir, 50)
	defer s.Close()

	for i := range 100 {
		s.Insert(uint64(i))
	}
	s.Delete(10)
	s.Delete(99)
	if s.Contains(10) {
		t.Errorf("Contains(10) = true after delete")
	}
	if s.Contains(99) {
		t.Errorf("Contains(99) = true after delete")
	}
	if !s.Contains(11) {
		t.Errorf("Contains(11) = false, should be present")
	}
}

func TestSwappableCompact(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewSwappable(dir, 50)
	defer s.Close()

	for i := range 200 {
		s.Insert(uint64(i))
	}
	s.Delete(0)
	s.Delete(100)
	s.Delete(199)

	if err := s.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if s.SegmentCount() != 1 {
		t.Errorf("SegmentCount after Compact = %d, want 1", s.SegmentCount())
	}
	if s.Len() != 197 {
		t.Errorf("Len after Compact = %d, want 197", s.Len())
	}
	if s.Contains(0) || s.Contains(100) || s.Contains(199) {
		t.Errorf("deleted keys still present after Compact")
	}
}

func TestSwappableSwapToDisk(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewSwappable(dir, 10_000)
	defer s.Close()

	for i := range 500 {
		s.Insert(uint64(i))
	}
	if s.SegmentCount() != 0 {
		t.Errorf("expected 0 segments before swap, got %d", s.SegmentCount())
	}
	if err := s.SwapToDisk(); err != nil {
		t.Fatalf("SwapToDisk: %v", err)
	}
	if s.SegmentCount() != 1 {
		t.Errorf("expected 1 segment after swap, got %d", s.SegmentCount())
	}
	for i := range 500 {
		if !s.Contains(uint64(i)) {
			t.Errorf("Contains(%d) = false after swap to disk", i)
		}
	}
}

func TestSwappableMerge(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewSwappable(dir, 100)
	defer s.Close()

	src := New()
	for i := range 300 {
		src.Insert(uint64(i))
	}
	if err := s.Merge(src); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if s.Len() != 300 {
		t.Errorf("Len after merge = %d, want 300", s.Len())
	}
}

// ─── real-nonce report ────────────────────────────────────────────────────────

// TestARTReport runs every measurement against the real nonce.jsonl data and
// prints a unified table.
//
//	go test -v -run TestARTReport ./art/
func TestARTReport(t *testing.T) {
	if len(allNonces) == 0 {
		t.Skip("no nonces loaded — skipping report")
	}
	n := len(allNonces)

	row := func(label, value string) {
		fmt.Printf("  %-38s  %s\n", label, value)
	}
	sep := func() { fmt.Println("  " + rep("─", 60)) }
	thick := func() { fmt.Println("  " + rep("═", 60)) }

	fmt.Println()
	thick()
	fmt.Printf("  ART Benchmark  ·  n = %s real nonces  ·  data/nonce.jsonl\n", fmtCount(n))
	thick()

	// ── 1. Build ART ─────────────────────────────────────────────────────────
	runtime.GC()
	runtime.GC()
	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)

	t0 := time.Now()
	idx := New()
	for _, k := range allNonces {
		idx.Insert(k)
	}
	buildTime := time.Since(t0)

	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms1)
	heapBytes := ms1.HeapAlloc - ms0.HeapAlloc

	row("Build ART (all nonces)", fmtD(buildTime))
	row("Keys indexed", fmt.Sprintf("%s", fmtCount(idx.Len())))
	row("Heap RAM (ART nodes)", fmtB(heapBytes))
	sep()

	// ── 2. Single insert ──────────────────────────────────────────────────────
	const insertReps = 1_000_000
	probe := uint64(0xDEADBEEFCAFEBABE)
	t0 = time.Now()
	for range insertReps {
		idx.Insert(probe)
	}
	singleInsert := time.Since(t0) / insertReps
	row("Single Insert (amortised, 1M reps)", fmtNs(singleInsert))
	sep()

	// ── 3. Contains (hit) ─────────────────────────────────────────────────────
	sample := evenlySampled(allNonces, 10_000)
	// warmup
	for _, k := range sample {
		idx.Contains(k)
	}
	t0 = time.Now()
	for range 3 {
		for _, k := range sample {
			idx.Contains(k)
		}
	}
	containsHit := time.Since(t0) / time.Duration(3*len(sample))
	row("Contains hit (avg, 10k sample)", fmtNs(containsHit))

	// miss
	t0 = time.Now()
	for range 3 {
		for _, k := range sample {
			idx.Contains(k + 1) // very likely absent
		}
	}
	containsMiss := time.Since(t0) / time.Duration(3*len(sample))
	row("Contains miss (avg, 10k sample)", fmtNs(containsMiss))
	sep()

	// ── 4. Wire encoding (Encode / Decode) ────────────────────────────────────
	rawBytes := idx.Len() * 8
	// warmup
	Encode(idx)
	t0 = time.Now()
	payload := Encode(idx)
	encodeTime := time.Since(t0)

	row("Wire size uncompressed (8 B/key)", fmtB(uint64(rawBytes)))
	row(fmt.Sprintf("Wire size zstd (%.1f%% of raw)", 100*float64(len(payload))/float64(rawBytes)),
		fmtB(uint64(len(payload))))
	row("Encode time (zstd, stream delta)", fmtD(encodeTime))

	// Decode
	Decode(payload) // warmup
	t0 = time.Now()
	decoded, err := Decode(payload)
	decodeTime := time.Since(t0)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Len() != idx.Len() {
		t.Errorf("decoded Len mismatch: got %d want %d", decoded.Len(), idx.Len())
	}
	row("Decode time (zstd decompress + insert)", fmtD(decodeTime))
	sep()

	// ── 5. Swap to disk ───────────────────────────────────────────────────────
	dir := t.TempDir()
	sw, _ := NewSwappable(dir, len(allNonces)+1) // high threshold = no auto-spill
	for _, k := range allNonces {
		sw.Insert(k)
	}

	t0 = time.Now()
	if err := sw.SwapToDisk(); err != nil {
		t.Fatalf("SwapToDisk: %v", err)
	}
	swapTime := time.Since(t0)

	// measure segment file size on disk
	entries, _ := os.ReadDir(dir)
	var diskBytes int64
	for _, e := range entries {
		if fi, err := os.Stat(filepath.Join(dir, e.Name())); err == nil {
			diskBytes += fi.Size()
		}
	}
	row("Swap to disk (zstd segment write)", fmtD(swapTime))
	row(fmt.Sprintf("Segment file size on disk (%.1f%% of raw)", 100*float64(diskBytes)/float64(rawBytes)),
		fmtB(uint64(diskBytes)))
	row("Segments written", fmt.Sprintf("%d", sw.SegmentCount()))
	sep()

	// ── 6. Load from disk (first access = cold cache) ─────────────────────────
	// Clear segment cache to simulate cold read from disk.
	for i := range sw.segments {
		sw.segments[i].cached = nil
	}
	probe2 := allNonces[len(allNonces)/2]
	t0 = time.Now()
	sw.Contains(probe2) // loads segment from disk, populates cache
	coldLoad := time.Since(t0)
	row("Contains after swap — cold (disk read + decompress)", fmtD(coldLoad))

	// warm cache hit
	t0 = time.Now()
	for range 10_000 {
		sw.Contains(probe2)
	}
	warmHit := time.Since(t0) / 10_000
	row("Contains after swap — warm (cached segment)", fmtNs(warmHit))
	sep()

	// ── 7. Delete ─────────────────────────────────────────────────────────────
	// Re-use in-memory idx for delete timing.
	deleteKey := allNonces[0]
	t0 = time.Now()
	for range insertReps {
		idx.Insert(deleteKey)  // ensure present
		idx.Delete(deleteKey)  // then delete
	}
	singleDelete := time.Since(t0) / insertReps / 2
	row("Single Delete (amortised, 1M reps)", fmtNs(singleDelete))

	thick()
	fmt.Println("  Build       = insert all n nonces into a fresh ART")
	fmt.Println("  HeapRAM     = live heap delta measured around build")
	fmt.Println("  Contains    = avg latency over 10k evenly-spaced nonces")
	fmt.Println("  Encode      = zstd stream, delta-encoded keys, no intermediate slice")
	fmt.Println("  Decode      = zstd decompress + ART rebuild from deltas")
	fmt.Println("  SwapToDisk  = flush hot ART → zstd segment file, clear hot")
	fmt.Println("  Cold load   = first Contains after swap (reads + decompresses file)")
	fmt.Println("  Warm load   = subsequent Contains (segment cached in memory)")
	thick()
	fmt.Println()
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func evenlySampled(nonces []uint64, k int) []uint64 {
	if len(nonces) <= k {
		return nonces
	}
	step := len(nonces) / k
	out := make([]uint64, k)
	for i := range k {
		out[i] = nonces[i*step]
	}
	return out
}

func fmtCount(n int) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.2fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func fmtD(d time.Duration) string {
	switch {
	case d >= time.Second:
		return fmt.Sprintf("%.2f s", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.1f ms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.1f µs", float64(d)/float64(time.Microsecond))
	}
}

func fmtNs(d time.Duration) string {
	if ns := float64(d); ns < 1000 {
		return fmt.Sprintf("%.1f ns", ns)
	}
	return fmt.Sprintf("%.1f µs", float64(d)/float64(time.Microsecond))
}

func fmtB(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func rep(s string, n int) string {
	b := make([]byte, n*len(s))
	for i := range n {
		copy(b[i*len(s):], s)
	}
	return string(b)
}

// ─── benchmarks ──────────────────────────────────────────────────────────────

const benchN = 1_000_000 // keys pre-loaded for Contains/Delete benchmarks

// ── Insert ────────────────────────────────────────────────────────────────────

func BenchmarkARTInsert(b *testing.B) {
	a := New()
	b.ResetTimer()
	for i := range b.N {
		a.Insert(uint64(i))
	}
}

func BenchmarkSwappableInsert_BelowThreshold(b *testing.B) {
	// threshold >> b.N so no disk flush ever happens — pure hot-path cost.
	dir := b.TempDir()
	s, _ := NewSwappable(dir, b.N+1)
	defer s.Close()
	b.ResetTimer()
	for i := range b.N {
		s.Insert(uint64(i)) //nolint:errcheck
	}
}

func BenchmarkSwappableInsert_WithSpill(b *testing.B) {
	// threshold = 10 k so flushes happen regularly — measures amortised cost.
	dir := b.TempDir()
	s, _ := NewSwappable(dir, 10_000)
	defer s.Close()
	b.ResetTimer()
	for i := range b.N {
		s.Insert(uint64(i)) //nolint:errcheck
	}
}

// ── Contains ─────────────────────────────────────────────────────────────────

func BenchmarkARTContains_Hit(b *testing.B) {
	a := New()
	for i := range benchN {
		a.Insert(uint64(i))
	}
	b.ResetTimer()
	for i := range b.N {
		a.Contains(uint64(i % benchN))
	}
}

func BenchmarkARTContains_Miss(b *testing.B) {
	a := New()
	for i := range benchN {
		a.Insert(uint64(i))
	}
	b.ResetTimer()
	for i := range b.N {
		a.Contains(uint64(benchN + i))
	}
}

func BenchmarkSwappableContains_Hot_Hit(b *testing.B) {
	// All keys in hot ART (threshold not reached).
	dir := b.TempDir()
	s, _ := NewSwappable(dir, benchN+1)
	defer s.Close()
	for i := range benchN {
		s.Insert(uint64(i)) //nolint:errcheck
	}
	b.ResetTimer()
	for i := range b.N {
		s.Contains(uint64(i % benchN))
	}
}

func BenchmarkSwappableContains_Segment_Warm(b *testing.B) {
	// All keys flushed to a segment; cache is warm after first access.
	dir := b.TempDir()
	s, _ := NewSwappable(dir, benchN+1)
	defer s.Close()
	for i := range benchN {
		s.Insert(uint64(i)) //nolint:errcheck
	}
	s.SwapToDisk() //nolint:errcheck
	// Warm the cache.
	s.Contains(0)
	b.ResetTimer()
	for i := range b.N {
		s.Contains(uint64(i % benchN))
	}
}

func BenchmarkSwappableContains_Segment_Cold(b *testing.B) {
	// Each iteration clears the segment cache to simulate a cold disk read.
	dir := b.TempDir()
	s, _ := NewSwappable(dir, benchN+1)
	defer s.Close()
	for i := range benchN {
		s.Insert(uint64(i)) //nolint:errcheck
	}
	s.SwapToDisk() //nolint:errcheck
	b.ResetTimer()
	for i := range b.N {
		// Clear cache before each lookup.
		for j := range s.segments {
			s.segments[j].cached = nil
		}
		s.Contains(uint64(i % benchN))
	}
}

// ── Delete ────────────────────────────────────────────────────────────────────

func BenchmarkARTDelete(b *testing.B) {
	a := New()
	for i := range benchN {
		a.Insert(uint64(i))
	}
	b.ResetTimer()
	for i := range b.N {
		k := uint64(i % benchN)
		a.Insert(k) // ensure present
		a.Delete(k)
	}
}

func BenchmarkSwappableDelete(b *testing.B) {
	dir := b.TempDir()
	s, _ := NewSwappable(dir, benchN+1)
	defer s.Close()
	for i := range benchN {
		s.Insert(uint64(i)) //nolint:errcheck
	}
	b.ResetTimer()
	for i := range b.N {
		k := uint64(i % benchN)
		s.Insert(k) //nolint:errcheck
		s.Delete(k)
	}
}

// ── Encode / Decode ───────────────────────────────────────────────────────────

func BenchmarkEncode(b *testing.B) {
	a := New()
	for i := range benchN {
		a.Insert(uint64(i))
	}
	b.ResetTimer()
	for range b.N {
		Encode(a)
	}
}

func BenchmarkDecode(b *testing.B) {
	a := New()
	for i := range benchN {
		a.Insert(uint64(i))
	}
	payload := Encode(a)
	b.ResetTimer()
	for range b.N {
		Decode(payload) //nolint:errcheck
	}
}

// ─── example ──────────────────────────────────────────────────────────────────

func ExampleSwappableART() {
	s, _ := NewSwappable(os.TempDir(), DefaultThreshold)
	defer s.Close()

	s.Insert(42)
	s.Insert(1000)
	fmt.Println(s.Contains(42))
	fmt.Println(s.Contains(99))
	s.Delete(42)
	fmt.Println(s.Contains(42))
	// Output:
	// true
	// false
	// false
}
