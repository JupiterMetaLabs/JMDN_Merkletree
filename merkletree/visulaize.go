package merkletree

import "fmt"

// Visualize prints the internal state of the Builder to stdout.
// Since this is a streaming builder, it only stores:
// 1. Attempts to visualize the current incomplete chunk (buffer).
// 2. The "Peaks" of the outer Merkle Mountain Range (accumulator).
// It does NOT store the history of all chunks, so it cannot print the full history.
func (b *Builder) Visualize() {
	fmt.Println()
	fmt.Println("════════════ Merkle Builder State ════════════")
	fmt.Printf("Total Blocks Processed : %d\n", b.totalBlocks)

	// ---- Partial chunk ----
	if len(b.inChunkElems) > 0 {
		start := b.inChunkStart
		end := start + uint64(len(b.inChunkElems)) - 1
		fmt.Printf("Partial Chunk          : %d / %d blocks\n", len(b.inChunkElems), b.cfg.BlockMerge)
		fmt.Printf("  Range                : [%d … %d]\n", start, end)
	} else {
		fmt.Printf("Partial Chunk          : (empty)\n")
	}

	fmt.Println()

	// ---- Outer accumulator (MMR peaks) ----
	fmt.Println("Outer Merkle Accumulator (MMR Peaks):")

	if len(b.outer.peaks) == 0 {
		fmt.Println("  (no committed chunks)")
	} else {
		found := false
		for level, p := range b.outer.peaks {
			if p == nil {
				continue
			}
			found = true

			// how many chunks this peak represents
			chunks := uint64(1) << level
			start := p.start
			end := start + uint64(p.count) - 1

			fmt.Printf("  ├─ Level %-2d  (%d chunks)\n", level, chunks)
			fmt.Printf("  │    Range : [%d … %d]\n", start, end)
			fmt.Printf("  │    Count : %d blocks\n", p.count)
			fmt.Printf("  │    Hash  : %s\n", shortHash(p.sum))
		}

		if !found {
			fmt.Println("  (all peaks nil)")
		}
	}

	fmt.Println("══════════════════════════════════════════════")
	fmt.Println()
}

func shortHash(h Hash32) string {
	// first 8 bytes is enough for debugging
	return fmt.Sprintf("%x…", h[:8])
}
