package art

// swappable.go — SwappableART: an ART index that automatically spills
// in-memory data to zstd-compressed segment files on disk when the
// in-memory key count exceeds a configurable threshold.
//
// Design:
//
//	hot       *ART                 — fast in-memory index (mutable)
//	segments  []*segment           — read-only on-disk blobs (immutable once written)
//	tombstone map[uint64]struct{}  — deleted keys (applied lazily to segments)
//
// Operations:
//
//	Insert(nonce)      — add to hot; auto-spills when hot.Len() >= threshold
//	Contains(nonce)    — tombstone → hot → segment min/max → segment binary search
//	Delete(nonce)      — tombstone + immediate hot delete; segments cleaned on Compact
//	Merge(src *ART)    — bulk insert from another ART
//	SwapToDisk()       — force-flush hot to disk now
//	Compact()          — merge hot + all segments into one segment, apply tombstones
//	Iter(f)            — iterate all live keys (hot + segments, tombstones filtered)
//	Len()              — total live count (hot + segments − tombstones)
//	Close()            — flush remaining hot data before shutdown

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// DefaultThreshold is the default number of in-memory keys that triggers
// an automatic spill to disk (~100 MB of ART nodes for random uint64 keys).
const DefaultThreshold = 1_000_000

// segment represents one on-disk zstd-compressed sorted key file.
// Pointers are used so lazy cache fill never copies a sync.Mutex (see loadSegment).
type segment struct {
	cacheMu sync.Mutex // protects lazy population of cached only
	path    string
	count   int
	min     uint64
	max     uint64
	cached  []uint64 // nil until first load; kept in memory after first access
}

// SwappableART wraps ART with disk-spill support.
// It is safe for concurrent use.
//
// Read scaling: Contains, Iter, Len, and SegmentCount use sync.RWMutex so many
// goroutines can read in parallel; writers take the exclusive lock.
type SwappableART struct {
	mu        sync.RWMutex
	hot       *ART
	tombstone map[uint64]struct{}
	segments  []*segment
	dir       string
	threshold int
	seq       int // segment file counter
}

// NewSwappable returns a SwappableART that spills to dir when the in-memory
// key count exceeds threshold. Use DefaultThreshold if unsure.
//
// The dir is created if it does not exist.
func NewSwappable(dir string, threshold int) (*SwappableART, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("art: create segment dir %s: %w", dir, err)
	}
	return &SwappableART{
		hot:       New(),
		tombstone: make(map[uint64]struct{}),
		dir:       dir,
		threshold: threshold,
	}, nil
}

// Insert adds nonce to the index. If the hot ART reaches the threshold,
// it is automatically flushed to a new on-disk segment.
// Returns a non-nil error only if the disk flush fails.
func (s *SwappableART) Insert(nonce uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tombstone, nonce) // resurrect if previously deleted
	s.hot.Insert(nonce)
	if s.hot.Len() >= s.threshold {
		return s.flushLocked()
	}
	return nil
}

// Contains returns true if nonce is present and not deleted.
// Checks (in order): tombstone → hot ART → each on-disk segment.
func (s *SwappableART) Contains(nonce uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, dead := s.tombstone[nonce]; dead {
		return false
	}
	if s.hot.Contains(nonce) {
		return true
	}
	for _, seg := range s.segments {
		if nonce < seg.min || nonce > seg.max {
			continue // fast range filter
		}
		keys, err := s.loadSegment(seg)
		if err != nil {
			continue
		}
		pos := sort.Search(len(keys), func(j int) bool { return keys[j] >= nonce })
		if pos < len(keys) && keys[pos] == nonce {
			return true
		}
	}
	return false
}

// Delete marks nonce as deleted. It is immediately removed from the hot ART;
// segment files are not modified until the next Compact call.
func (s *SwappableART) Delete(nonce uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tombstone[nonce] = struct{}{}
	s.hot.Delete(nonce)
}

// Merge inserts all keys from src into s.
// Returns the first flush error encountered, if any.
func (s *SwappableART) Merge(src *ART) error {
	var firstErr error
	src.Iter(func(k uint64) {
		if firstErr != nil {
			return
		}
		firstErr = s.Insert(k)
	})
	return firstErr
}

// SwapToDisk force-flushes the hot in-memory ART to a new segment file
// and clears the hot ART.
func (s *SwappableART) SwapToDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

// Compact merges all data (hot + every on-disk segment) into a single
// on-disk segment, applying tombstone deletions in the process.
// The hot ART is cleared and old segment files are removed.
func (s *SwappableART) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	merged := New()

	// Merge hot keys (filter tombstones).
	s.hot.Iter(func(k uint64) {
		if _, dead := s.tombstone[k]; !dead {
			merged.Insert(k)
		}
	})

	// Merge all segments (filter tombstones).
	for _, seg := range s.segments {
		keys, err := s.loadSegment(seg)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if _, dead := s.tombstone[k]; !dead {
				merged.Insert(k)
			}
		}
	}

	// Remove old segment files.
	for _, seg := range s.segments {
		_ = os.Remove(seg.path)
	}
	s.segments = s.segments[:0]
	s.tombstone = make(map[uint64]struct{})

	// Write the compacted tree as a new segment.
	s.hot = merged
	return s.flushLocked()
}

// Iter calls f for every live key across hot and all segments.
// Keys are not delivered in sorted order across segment boundaries;
// call Compact first if sorted iteration is required.
// Returns the first segment-load error, if any.
func (s *SwappableART) Iter(f func(uint64)) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.hot.Iter(func(k uint64) {
		if _, dead := s.tombstone[k]; !dead {
			f(k)
		}
	})

	for _, seg := range s.segments {
		keys, err := s.loadSegment(seg)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if _, dead := s.tombstone[k]; !dead {
				f(k)
			}
		}
	}
	return nil
}

// Len returns the total logical key count (hot + segments − tombstones).
func (s *SwappableART) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := s.hot.Len()
	for _, seg := range s.segments {
		total += seg.count
	}
	return total - len(s.tombstone)
}

// Close flushes any remaining hot data to disk.
func (s *SwappableART) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hot.Len() > 0 {
		return s.flushLocked()
	}
	return nil
}

// SegmentCount returns the number of on-disk segments (useful for monitoring).
func (s *SwappableART) SegmentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.segments)
}

// ─── internal helpers ─────────────────────────────────────────────────────────

// segEncodeKeys delta-encodes and zstd-compresses a sorted uint64 slice for
// on-disk segment storage. Separate from the wire codec (Encode/Decode) to
// keep disk and network serialisation independent.
func segEncodeKeys(keys []uint64) []byte {
	var out bytes.Buffer
	out.Grow(8 + len(keys)*8/8)

	zw := encoderPool.Get().(*zstd.Encoder)
	zw.Reset(&out)

	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(len(keys)))
	zw.Write(hdr[:]) //nolint:errcheck

	var buf [8]byte
	var prev uint64
	for _, k := range keys {
		binary.BigEndian.PutUint64(buf[:], k-prev)
		prev = k
		zw.Write(buf[:]) //nolint:errcheck
	}
	zw.Close()           //nolint:errcheck
	encoderPool.Put(zw)
	return out.Bytes()
}

// segDecodeKeys decompresses a segment blob back to a sorted uint64 slice.
func segDecodeKeys(data []byte) ([]uint64, error) {
	raw, err := getDecoder().DecodeAll(data, nil)
	if err != nil {
		return nil, fmt.Errorf("art: segment zstd decode: %w", err)
	}
	if len(raw) < 8 {
		return nil, fmt.Errorf("art: segment too short")
	}
	count := int(binary.BigEndian.Uint64(raw))
	if len(raw) < 8+count*8 {
		return nil, fmt.Errorf("art: segment truncated (need %d, got %d)", 8+count*8, len(raw))
	}
	keys := make([]uint64, count)
	var cur uint64
	for i := range count {
		cur += binary.BigEndian.Uint64(raw[8+i*8:])
		keys[i] = cur
	}
	return keys, nil
}

// flushLocked writes the hot ART to a new zstd segment file and clears hot.
// Caller must hold s.mu.
func (s *SwappableART) flushLocked() error {
	if s.hot.Len() == 0 {
		return nil
	}

	keys := s.hot.Keys() // already sorted by ART walk order

	path := filepath.Join(s.dir, fmt.Sprintf("seg-%06d.art.zst", s.seq))
	s.seq++

	compressed := segEncodeKeys(keys)
	if err := os.WriteFile(path, compressed, 0o644); err != nil {
		return fmt.Errorf("art: flush segment %s: %w", path, err)
	}

	seg := &segment{
		path:   path,
		count:  len(keys),
		cached: keys, // keep first batch in memory; reloaded on subsequent access
	}
	if len(keys) > 0 {
		seg.min = keys[0]
		seg.max = keys[len(keys)-1]
	}
	s.segments = append(s.segments, seg)
	s.hot.Clear()
	return nil
}

// loadSegment returns the sorted key slice for seg, loading from disk if not
// already cached. The result is cached in seg.cached for future calls.
// cacheMu serializes the first load per segment when many goroutines call Contains
// with RLock on the SwappableART.
func (s *SwappableART) loadSegment(seg *segment) ([]uint64, error) {
	seg.cacheMu.Lock()
	defer seg.cacheMu.Unlock()
	if seg.cached != nil {
		return seg.cached, nil
	}
	data, err := os.ReadFile(seg.path)
	if err != nil {
		return nil, fmt.Errorf("art: read segment %s: %w", seg.path, err)
	}
	keys, err := segDecodeKeys(data)
	if err != nil {
		return nil, err
	}
	seg.cached = keys
	return keys, nil
}
