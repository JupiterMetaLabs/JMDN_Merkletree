package merkletree

import (
	"context"
	"sort"
	"sync"
)

// DiffRange represents a range of blocks that differ between two trees.
type DiffRange struct {
	Start uint64 `json:"start"`
	Count uint32 `json:"count"`
}

// MultiBisect finds ALL chunks/ranges that differ between this builder and another.
// It uses parallel execution to traverse independent subtrees concurrently.
// concurrency: Maximum number of goroutines to use (e.g., 4 or 8).
func (b *Builder) MultiBisect(other *Builder, concurrency int) ([]DiffRange, error) {
	if concurrency < 1 {
		concurrency = 1
	}

	var mu sync.Mutex
	var diffs []DiffRange

	// Channel to limit concurrency (semaphore)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// Helper to check leaf or recurse
	var checkNode func(n1, n2 *Node)
	checkNode = func(n1, n2 *Node) {
		defer wg.Done()

		// If one is nil and other isn't, whole range is diff.
		if n1 == nil || n2 == nil {
			var start uint64
			var count uint32
			if n1 != nil {
				start, count = n1.Metadata.Start, n1.Metadata.Count
			} else {
				start, count = n2.Metadata.Start, n2.Metadata.Count
			}
			mu.Lock()
			diffs = append(diffs, DiffRange{Start: start, Count: count})
			mu.Unlock()
			return
		}

		// Sanity check: if roots match, no diff here.
		// (This should be checked before spawning, but safe to check here too)
		if n1.Root == n2.Root {
			return
		}

		// If Leaf, we found a specific mismatched chunk.
		if n1.HasData {
			mu.Lock()
			diffs = append(diffs, DiffRange{Start: n1.Metadata.Start, Count: n1.Metadata.Count})
			mu.Unlock()
			return
		}

		// Internal Node: Check children
		// Parallelize Left if needed
		if n1.Left != nil || n2.Left != nil {
			// Check root of left children without recursing yet
			var leftRoot1, leftRoot2 Hash32
			if n1.Left != nil {
				leftRoot1 = n1.Left.Root
			}
			if n2.Left != nil {
				leftRoot2 = n2.Left.Root
			}

			if leftRoot1 != leftRoot2 {
				// Try to spawn goroutine
				select {
				case sem <- struct{}{}:
					wg.Add(1)
					go func() {
						defer func() { <-sem }()
						checkNode(n1.Left, n2.Left)
					}()
				default:
					// No slot, run synchronously (but we still need waitgroup for consistency of recursion pattern)
					wg.Add(1)
					checkNode(n1.Left, n2.Left)
				}
			}
		}

		// Parallelize Right if needed
		if n1.Right != nil || n2.Right != nil {
			var rightRoot1, rightRoot2 Hash32
			if n1.Right != nil {
				rightRoot1 = n1.Right.Root
			}
			if n2.Right != nil {
				rightRoot2 = n2.Right.Root
			}

			if rightRoot1 != rightRoot2 {
				// Try to spawn goroutine
				select {
				case sem <- struct{}{}:
					wg.Add(1)
					go func() {
						defer func() { <-sem }()
						checkNode(n1.Right, n2.Right)
					}()
				default:
					wg.Add(1)
					checkNode(n1.Right, n2.Right)
				}
			}
		}
	}

	// 1. Compare Peaks (Roots of large subtrees)
	peaks1 := b.outer.peaks
	peaks2 := other.outer.peaks
	maxLevel := len(peaks1)
	if len(peaks2) > maxLevel {
		maxLevel = len(peaks2)
	}

	for i := maxLevel - 1; i >= 0; i-- {
		var p1, p2 *Node
		if i < len(peaks1) {
			p1 = peaks1[i]
		}
		if i < len(peaks2) {
			p2 = peaks2[i]
		}

		if p1 == nil && p2 == nil {
			continue
		}

		// If roots differ, start traversal
		var root1, root2 Hash32
		if p1 != nil {
			root1 = p1.Root
		}
		if p2 != nil {
			root2 = p2.Root
		}

		if root1 != root2 {
			wg.Add(1)
			// Initial launch
			go func(a, b *Node) {
				// Acquire semaphore for initial launch? Or just run.
				// Let's acquire to respect concurrency limit even at top level
				sem <- struct{}{}
				defer func() { <-sem }()
				checkNode(a, b)
			}(p1, p2)
		}
	}

	// 2. Compare Partial Buffer (Synchronously, usually small)
	if len(b.inChunkElems) != len(other.inChunkElems) {
		// Length mismatch in partial buffer -> mismatch entire buffer range
		// We use the start of whichever buffer exists
		start := b.inChunkStart
		if len(other.inChunkElems) > 0 {
			start = other.inChunkStart // should be same
		}
		// Count is max of valid ranges? Or min? usually partial end is same logic.
		count := uint32(len(b.inChunkElems))
		if len(other.inChunkElems) > int(count) {
			count = uint32(len(other.inChunkElems))
		}
		if count > 0 {
			mu.Lock()
			diffs = append(diffs, DiffRange{Start: start, Count: count})
			mu.Unlock()
		}
	} else {
		// Same length, check content
		diff := false
		for i := range b.inChunkElems {
			if b.inChunkElems[i] != other.inChunkElems[i] {
				diff = true
				break
			}
		}
		if diff {
			mu.Lock()
			diffs = append(diffs, DiffRange{Start: b.inChunkStart, Count: uint32(len(b.inChunkElems))})
			mu.Unlock()
		}
	}

	// Wait for all traversals
	wg.Wait()

	// Sort results by Start block for consistent output
	return consolidateDiffs(diffs), nil
}

// consolidateDiffs sorts and merges overlapping or adjacent ranges.
func consolidateDiffs(diffs []DiffRange) []DiffRange {
	if len(diffs) == 0 {
		return nil
	}

	// Sort by Start, then by End (Count)
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Start == diffs[j].Start {
			return diffs[i].Count > diffs[j].Count // Larger count first to consume smaller ones
		}
		return diffs[i].Start < diffs[j].Start
	})

	var result []DiffRange
	current := diffs[0]

	for i := 1; i < len(diffs); i++ {
		next := diffs[i]

		// Check overlap or adjournment
		// End of current range (inclusive)
		currEnd := current.Start + uint64(current.Count)
		// Start of next range
		nextStart := next.Start

		if nextStart <= currEnd {
			// Overlap or touch
			nextEnd := next.Start + uint64(next.Count)
			if nextEnd > currEnd {
				// Extend current range
				current.Count = uint32(nextEnd - current.Start)
			}
		} else {
			// No overlap, push current and start new
			result = append(result, current)
			current = next
		}
	}
	result = append(result, current)

	return result
}

// Helper to use context cancellation if needed in future
func (b *Builder) MultiBisectWithContext(ctx context.Context, other *Builder, concurrency int) ([]DiffRange, error) {
	// Wrapper around MultiBisect that checks ctx.Done()?
	// For now, implementing basic MultiBisect as requested.
	// This creates a dedicated file for multi-bisection.
	return b.MultiBisect(other, concurrency)
}
