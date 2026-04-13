// Package bench benchmarks all DIDIndex implementations using real DID nonces.
//
// Nonces are loaded once from data/nonce.jsonl (schema: {"address":"0x...","nonce":uint64})
// into memory via TestMain, then reused for every benchmark — no IO during runs.
//
// Print the full comparison table:
//
//	go test -v -run TestFullReport ./DIDIndex/bench/
//
// Run micro-benchmarks:
//
//	go test -bench=. -benchmem ./DIDIndex/bench/
package bench

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	didindex "github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex"
	"github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex/art"
	"github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex/bptree"
	"github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex/finger"
	"github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex/fractal"
	"github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex/hybrid"
	"github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex/lsm"
	"github.com/JupiterMetaLabs/JMDN_Merkletree/DIDIndex/roaring"
)

// ─── real nonce data (loaded once in TestMain) ────────────────────────────────

var (
	allNonces []uint64 // all nonces from nonce.jsonl
	halfA     []uint64 // first half  (for merge benchmark)
	halfB     []uint64 // second half (for merge benchmark)
)

// TestMain loads nonce.jsonl into memory once before any test or benchmark runs.
func TestMain(m *testing.M) {
	path := filepath.Join("..", "..", "data", "nonce.jsonl")
	fmt.Printf("Loading nonces from %s ...\n", path)

	var err error
	allNonces, err = loadNonces(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR loading nonces: %v\n", err)
		os.Exit(1)
	}

	mid := len(allNonces) / 2
	halfA = allNonces[:mid]
	halfB = allNonces[mid:]

	fmt.Printf("Loaded %d nonces (%.1f MB in RAM)\n\n",
		len(allNonces), float64(len(allNonces)*8)/(1<<20))

	os.Exit(m.Run())
}

// loadNonces parses a JSONL file of {"address":"0x...","nonce":uint64} records.
// Uses an 8 MB read buffer and json.Decoder for efficient streaming.
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

	nonces := make([]uint64, 0, 3_000_000) // pre-allocate near expected size
	var e entry
	for dec.More() {
		e.Nonce = 0
		if err := dec.Decode(&e); err != nil {
			continue // skip malformed lines
		}
		nonces = append(nonces, e.Nonce)
	}
	return nonces, nil
}

// ─── algorithm registry ──────────────────────────────────────────────────────

type factory struct {
	name string
	new  func() didindex.DIDIndex
}

func allImpls() []factory {
	return []factory{
		{"ART", func() didindex.DIDIndex { return art.New() }},
		{"B+Tree", func() didindex.DIDIndex { return bptree.New() }},
		{"LSM", func() didindex.DIDIndex { return lsm.New() }},
		{"Roaring", func() didindex.DIDIndex { return roaring.New() }},
		{"FingerTree", func() didindex.DIDIndex { return finger.New() }},
		{"FractalTree", func() didindex.DIDIndex { return fractal.New() }},
		{"Hybrid[REC]", func() didindex.DIDIndex { return hybrid.New() }},
	}
}

// nativeMarshaler is implemented by Roaring and Hybrid.
type nativeMarshaler interface {
	NativeMarshal() []byte
}

// ─── full report ─────────────────────────────────────────────────────────────

type metrics struct {
	name            string
	heapBytes       uint64
	flatBytes       int
	nativeBytes     int
	nativeGzipBytes int
	flatGzipBytes   int
	nativeZstdBytes int
	flatZstdBytes   int
	nativeIsCompact bool
	insertSeq       time.Duration
	containsHit     time.Duration
	merge           time.Duration
	decompress      time.Duration
	gzipTime        time.Duration
	zstdTime        time.Duration
	gzipDecompress  time.Duration
	zstdDecompress  time.Duration
}

// TestFullReport builds each index from the real nonce.jsonl data and prints
// the unified comparison table.
//
//	go test -v -run TestFullReport ./DIDIndex/bench/
func TestFullReport(t *testing.T) {
	nonces := allNonces
	n := len(nonces)

	// Fewer reps for large datasets to keep wall time reasonable.
	// At 2.6M nonces even 3 reps per algo can take a while for slow algos.
	const warmup = 1
	const reps = 3

	results := make([]metrics, 0, len(allImpls()))

	for _, f := range allImpls() {
		m := metrics{name: f.name}

		// ── memory footprint ─────────────────────────────────────────────────
		runtime.GC()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		idx := f.new()
		for _, v := range nonces {
			idx.Insert(v)
		}
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&after)
		m.heapBytes = after.HeapAlloc - before.HeapAlloc

		// ── storage & compression ────────────────────────────────────────────
		flat := didindex.Marshal(idx)
		m.flatBytes = len(flat)

		var native []byte
		if nm, ok := idx.(nativeMarshaler); ok {
			native = nm.NativeMarshal()
			m.nativeIsCompact = true
		} else {
			native = flat
		}
		m.nativeBytes = len(native)

		var ngzBuf bytes.Buffer
		ngz, _ := gzip.NewWriterLevel(&ngzBuf, gzip.BestCompression)
		ngz.Write(native)
		ngz.Close()
		m.nativeGzipBytes = ngzBuf.Len()

		var fgzBuf bytes.Buffer
		fgz, _ := gzip.NewWriterLevel(&fgzBuf, gzip.BestCompression)
		fgz.Write(flat)
		fgz.Close()
		m.flatGzipBytes = fgzBuf.Len()

		// compressed payload for decompress timing
		var cBuf bytes.Buffer
		cw, _ := gzip.NewWriterLevel(&cBuf, gzip.BestSpeed)
		cw.Write(flat)
		cw.Close()
		payload := cBuf.Bytes()

		// ── insert sequential ────────────────────────────────────────────────
		for range warmup {
			tmp := f.new()
			for _, v := range nonces {
				tmp.Insert(v)
			}
		}
		t0 := time.Now()
		for range reps {
			tmp := f.new()
			for _, v := range nonces {
				tmp.Insert(v)
			}
		}
		m.insertSeq = time.Since(t0) / time.Duration(reps)

		// ── contains (hit) ───────────────────────────────────────────────────
		// Sample 10k evenly-spaced nonces to keep this fast.
		sample := makeSample(nonces, 10_000)
		for range warmup {
			for _, v := range sample {
				idx.Contains(v)
			}
		}
		t0 = time.Now()
		for range reps {
			for _, v := range sample {
				idx.Contains(v)
			}
		}
		m.containsHit = time.Since(t0) / time.Duration(reps*len(sample))

		// ── merge ────────────────────────────────────────────────────────────
		for range warmup {
			a, b := f.new(), f.new()
			for _, v := range halfA {
				a.Insert(v)
			}
			for _, v := range halfB {
				b.Insert(v)
			}
			a.Merge(b)
		}
		t0 = time.Now()
		for range reps {
			a, b := f.new(), f.new()
			for _, v := range halfA {
				a.Insert(v)
			}
			for _, v := range halfB {
				b.Insert(v)
			}
			a.Merge(b)
		}
		m.merge = time.Since(t0) / time.Duration(reps)

		// ── decompress + unmarshal ────────────────────────────────────────────
		for range warmup {
			gr, _ := gzip.NewReader(bytes.NewReader(payload))
			dec, _ := io.ReadAll(gr)
			gr.Close()
			didindex.Unmarshal(f.new(), dec)
		}
		t0 = time.Now()
		for range reps {
			gr, _ := gzip.NewReader(bytes.NewReader(payload))
			dec, _ := io.ReadAll(gr)
			gr.Close()
			didindex.Unmarshal(f.new(), dec)
		}
		m.decompress = time.Since(t0) / time.Duration(reps)

		results = append(results, m)
	}

	printTable(results, n)
}

// makeSample returns k evenly-spaced elements from nonces.
func makeSample(nonces []uint64, k int) []uint64 {
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

// ─── ART table (with zstd columns) ───────────────────────────────────────────

func printARTTable(rows []metrics, n int) {
	thick := rep("═", 160)
	sep := rep("─", 160)

	fmt.Printf("\n%s\n", thick)
	fmt.Printf("  ART Index Benchmark  ·  n = %s real nonces  ·  source: data/nonce.jsonl\n", fmtCount(n))
	fmt.Printf("%s\n", thick)

	// header — speed | storage sizes | compression timing
	fmt.Printf("  %-12s │ %9s │ %9s │ %9s │ %9s │ %9s │ %9s │ %9s │ %9s │ %9s │ %9s │ %9s │ %9s\n",
		"Algorithm",
		"Insert", "Contains", "Merge", "HeapAlloc",
		"Before(flat)", "Gzip size", "Zstd size",
		"GzipCmpr", "ZstdCmpr", "GzipDecmp", "ZstdDecmp",
		"HeapRAM",
	)
	fmt.Printf("  %-12s │ %9s │ %9s │ %9s │ %9s │ %12s │ %9s │ %9s │ %9s │ %9s │ %9s │ %9s\n",
		"",
		"(seq/op)", "(ns/key)", "(op)", "(RAM)",
		"(8B/key)", "(bytes)", "(bytes)",
		"(time)", "(time)", "(time)", "(time)",
	)
	fmt.Printf("  %s\n", sep)

	for _, r := range rows {
		gzRatio := 100.0 * float64(r.flatGzipBytes) / float64(r.flatBytes)
		zstdRatio := 100.0 * float64(r.flatZstdBytes) / float64(r.flatBytes)
		fmt.Printf("  %-12s │ %9s │ %9s │ %9s │ %9s │ %12s │ %9s (%.1f%%) │ %9s (%.1f%%) │ %9s │ %9s │ %9s │ %9s\n",
			r.name,
			fmtD(r.insertSeq), fmtNs(r.containsHit), fmtD(r.merge),
			fmtB(r.heapBytes),
			fmtB(uint64(r.flatBytes)),
			fmtB(uint64(r.flatGzipBytes)), gzRatio,
			fmtB(uint64(r.flatZstdBytes)), zstdRatio,
			fmtD(r.gzipTime), fmtD(r.zstdTime),
			fmtD(r.gzipDecompress), fmtD(r.zstdDecompress),
		)
	}

	fmt.Printf("  %s\n", thick)
	fmt.Println("  Insert      = full build from all n real nonces")
	fmt.Println("  Contains    = avg over 10k evenly-sampled lookups (hit path)")
	fmt.Println("  Merge       = build(n/2) + build(n/2) + Merge()")
	fmt.Println("  HeapAlloc   = live heap after building the index")
	fmt.Println("  Before(flat)= uncompressed wire size (sorted uint64, 8 B/key)")
	fmt.Println("  Gzip size   = compressed size + ratio vs flat (BestCompression)")
	fmt.Println("  Zstd size   = compressed size + ratio vs flat (BestCompression)")
	fmt.Println("  GzipCmpr    = gzip compression time")
	fmt.Println("  ZstdCmpr    = zstd compression time")
	fmt.Println("  GzipDecmp   = gzip decompress + Unmarshal time")
	fmt.Println("  ZstdDecmp   = zstd decompress + Unmarshal time")
	fmt.Printf("%s\n\n", thick)
}

// ─── table printer ────────────────────────────────────────────────────────────

func printTable(rows []metrics, n int) {
	const (
		wAlgo  = 18
		wSpeed = 11
		wStore = 10
		wRatio = 7
	)
	width := 2 + wAlgo + 4*(3+wSpeed) + 4*(3+wStore) + 2*(3+wRatio+1)
	thick := rep("═", width)
	sep := rep("─", width)

	fmt.Printf("\n%s\n", thick)
	fmt.Printf("  DID Index Benchmark  ·  n = %s real nonces  ·  source: data/nonce.jsonl\n", fmtCount(n))
	fmt.Printf("%s\n", thick)

	fmt.Printf("  %-*s │ %-*s │ %-*s │ %-*s\n",
		wAlgo, "",
		4*(3+wSpeed)-3, "◀─────────── Speed ────────────▶",
		4*(3+wStore)-3, "◀──────── Storage ─────────▶",
		2*(3+wRatio+1)-3, "◀ Compression ▶",
	)
	fmt.Printf("  %s\n", sep)

	fmt.Printf("  %-*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s\n",
		wAlgo, "Algorithm",
		wSpeed, "Insert", wSpeed, "Contains", wSpeed, "Merge", wSpeed, "Decompress",
		wStore, "HeapAlloc", wStore, "Flat wire", wStore, "Native", wStore, "Gzip(nat)",
		wRatio+1, "Flat→Gzip", wRatio+1, "Nat→Gzip",
	)
	fmt.Printf("  %-*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s\n",
		wAlgo, "",
		wSpeed, "(seq/op)", wSpeed, "(ns/key)", wSpeed, "(op)", wSpeed, "+Unmarshal",
		wStore, "(RAM)", wStore, "(8B/key)", wStore, "(compact)", wStore, "(BestCmpr)",
		wRatio+1, "ratio", wRatio+1, "ratio",
	)
	fmt.Printf("  %s\n", sep)

	for _, r := range rows {
		flatRatio := 100.0 * float64(r.flatGzipBytes) / float64(r.flatBytes)
		natRatio := 100.0 * float64(r.nativeGzipBytes) / float64(r.nativeBytes)
		natLabel := fmtB(uint64(r.nativeBytes))
		if r.nativeIsCompact {
			natLabel += " ◀"
		}
		fmt.Printf("  %-*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*s │ %*.1f%% │ %*.1f%%\n",
			wAlgo, r.name,
			wSpeed, fmtD(r.insertSeq), wSpeed, fmtNs(r.containsHit),
			wSpeed, fmtD(r.merge), wSpeed, fmtD(r.decompress),
			wStore, fmtB(r.heapBytes), wStore, fmtB(uint64(r.flatBytes)),
			wStore, natLabel, wStore, fmtB(uint64(r.nativeGzipBytes)),
			wRatio, flatRatio, wRatio, natRatio,
		)
	}

	fmt.Printf("  %s\n", thick)
	fmt.Println("  Insert     = full build from all n real nonces")
	fmt.Println("  Contains   = avg over 10k evenly-sampled lookups (hit path)")
	fmt.Println("  Merge      = build(n/2) + build(n/2) + Merge()")
	fmt.Println("  Decompress = gzip decompress + Unmarshal into fresh index")
	fmt.Println("  Flat wire  = sorted uint64 stream, 8 B/key (same for all)")
	fmt.Println("  Native ◀   = compact container format (Roaring/Hybrid only)")
	fmt.Println("  Gzip(nat)  = gzip BestCompression on native format")
	fmt.Printf("%s\n\n", thick)
}

// ─── formatting helpers ───────────────────────────────────────────────────────

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
	if ns := float64(d.Nanoseconds()); ns < 1000 {
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

func fmtCount(n int) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.2fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func rep(s string, n int) string {
	b := make([]byte, n*len(s))
	for i := range n {
		copy(b[i*len(s):], s)
	}
	return string(b)
}

// TestARTReport runs the full benchmark table for the ART algorithm only.
//
//	go test -v -run TestARTReport ./DIDIndex/bench/
func TestARTReport(t *testing.T) {
	impls := []factory{
		{"ART", func() didindex.DIDIndex { return art.New() }},
	}

	nonces := allNonces
	n := len(nonces)
	const warmup = 1
	const reps = 3

	results := make([]metrics, 0, 1)

	for _, f := range impls {
		m := metrics{name: f.name}

		runtime.GC()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		idx := f.new()
		for _, v := range nonces {
			idx.Insert(v)
		}
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&after)
		m.heapBytes = after.HeapAlloc - before.HeapAlloc

		flat := didindex.Marshal(idx)
		m.flatBytes = len(flat)

		var native []byte
		if nm, ok := idx.(nativeMarshaler); ok {
			native = nm.NativeMarshal()
			m.nativeIsCompact = true
		} else {
			native = flat
		}
		m.nativeBytes = len(native)

		// ── gzip compression size + timing ──────────────────────────────────
		t0 := time.Now()
		for range reps {
			var buf bytes.Buffer
			gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			gz.Write(flat)
			gz.Close()
			m.flatGzipBytes = buf.Len()
		}
		m.gzipTime = time.Since(t0) / time.Duration(reps)

		var ngzBuf bytes.Buffer
		ngz, _ := gzip.NewWriterLevel(&ngzBuf, gzip.BestCompression)
		ngz.Write(native)
		ngz.Close()
		m.nativeGzipBytes = ngzBuf.Len()

		// ── zstd compression size + timing ───────────────────────────────────
		zenc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		t0 = time.Now()
		for range reps {
			m.flatZstdBytes = len(zenc.EncodeAll(flat, nil))
		}
		m.zstdTime = time.Since(t0) / time.Duration(reps)
		m.nativeZstdBytes = len(zenc.EncodeAll(native, nil))

		// ── gzip decompress payload (BestSpeed for wire realism) ─────────────
		var gzPayBuf bytes.Buffer
		gzCW, _ := gzip.NewWriterLevel(&gzPayBuf, gzip.BestSpeed)
		gzCW.Write(flat)
		gzCW.Close()
		gzPayload := gzPayBuf.Bytes()

		for range warmup {
			gr, _ := gzip.NewReader(bytes.NewReader(gzPayload))
			dec, _ := io.ReadAll(gr)
			gr.Close()
			didindex.Unmarshal(f.new(), dec)
		}
		t0 = time.Now()
		for range reps {
			gr, _ := gzip.NewReader(bytes.NewReader(gzPayload))
			dec, _ := io.ReadAll(gr)
			gr.Close()
			didindex.Unmarshal(f.new(), dec)
		}
		m.gzipDecompress = time.Since(t0) / time.Duration(reps)

		// ── zstd decompress payload ──────────────────────────────────────────
		zstdPayload := zenc.EncodeAll(flat, nil)
		zdec, _ := zstd.NewReader(nil)
		for range warmup {
			dec, _ := zdec.DecodeAll(zstdPayload, nil)
			didindex.Unmarshal(f.new(), dec)
		}
		t0 = time.Now()
		for range reps {
			dec, _ := zdec.DecodeAll(zstdPayload, nil)
			didindex.Unmarshal(f.new(), dec)
		}
		m.zstdDecompress = time.Since(t0) / time.Duration(reps)
		m.decompress = m.gzipDecompress // keep compat field

		// ── insert sequential ────────────────────────────────────────────────
		for range warmup {
			tmp := f.new()
			for _, v := range nonces {
				tmp.Insert(v)
			}
		}
		t0 = time.Now()
		for range reps {
			tmp := f.new()
			for _, v := range nonces {
				tmp.Insert(v)
			}
		}
		m.insertSeq = time.Since(t0) / time.Duration(reps)

		// ── contains (hit) ───────────────────────────────────────────────────
		sample := makeSample(nonces, 10_000)
		for range warmup {
			for _, v := range sample {
				idx.Contains(v)
			}
		}
		t0 = time.Now()
		for range reps {
			for _, v := range sample {
				idx.Contains(v)
			}
		}
		m.containsHit = time.Since(t0) / time.Duration(reps*len(sample))

		// ── merge ────────────────────────────────────────────────────────────
		for range warmup {
			a, b := f.new(), f.new()
			for _, v := range halfA { a.Insert(v) }
			for _, v := range halfB { b.Insert(v) }
			a.Merge(b)
		}
		t0 = time.Now()
		for range reps {
			a, b := f.new(), f.new()
			for _, v := range halfA { a.Insert(v) }
			for _, v := range halfB { b.Insert(v) }
			a.Merge(b)
		}
		m.merge = time.Since(t0) / time.Duration(reps)

		results = append(results, m)
	}

	printARTTable(results, n)
}

// ─── micro-benchmarks (go test -bench=.) ─────────────────────────────────────

func BenchmarkInsertSequential(b *testing.B) {
	nonces := allNonces
	for _, f := range allImpls() {
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				idx := f.new()
				for _, v := range nonces {
					idx.Insert(v)
				}
			}
		})
	}
}

func BenchmarkContains(b *testing.B) {
	sample := makeSample(allNonces, 10_000)
	for _, f := range allImpls() {
		idx := f.new()
		for _, v := range allNonces {
			idx.Insert(v)
		}
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := range b.N {
				idx.Contains(sample[i%len(sample)])
			}
		})
	}
}

func BenchmarkMerge(b *testing.B) {
	for _, f := range allImpls() {
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				a, bIdx := f.new(), f.new()
				for _, v := range halfA {
					a.Insert(v)
				}
				for _, v := range halfB {
					bIdx.Insert(v)
				}
				a.Merge(bIdx)
			}
		})
	}
}

func BenchmarkDecompress(b *testing.B) {
	for _, f := range allImpls() {
		idx := f.new()
		for _, v := range allNonces {
			idx.Insert(v)
		}
		raw := didindex.Marshal(idx)
		var buf bytes.Buffer
		gz, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		gz.Write(raw)
		gz.Close()
		payload := buf.Bytes()

		b.Run(f.name, func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for range b.N {
				gr, _ := gzip.NewReader(bytes.NewReader(payload))
				dec, _ := io.ReadAll(gr)
				gr.Close()
				didindex.Unmarshal(f.new(), dec)
			}
		})
	}
}
