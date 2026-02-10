package merkletree

import (
	"fmt"
)

// TreeDiff traverses the entire structure of two trees (starting from RootNode)
// and returns ALL ranges that differ or are missing.
//
// It is useful for full synchronization where you want to identify all
// discrepancies in one pass, rather than just the first one.
func (b *Builder) TreeDiff(other *Builder) ([]DiffRange, error) {
	root1, err := b.RootNode()
	if err != nil {
		return nil, fmt.Errorf("failed to get root node for self: %w", err)
	}
	root2, err := other.RootNode()
	if err != nil {
		return nil, fmt.Errorf("failed to get root node for other: %w", err)
	}

	return b.diffIterative(root1, root2)
}

func (b *Builder) diffIterative(root1, root2 *Node) ([]DiffRange, error) {
	var diffs []DiffRange

	// Stack for Tree 1
	stack1 := []*Node{root1}
	// Stack for Tree 2
	stack2 := []*Node{root2}

	for len(stack1) > 0 || len(stack2) > 0 {
		var n1, n2 *Node

		// Peek from stacks
		if len(stack1) > 0 {
			n1 = stack1[len(stack1)-1]
		}
		if len(stack2) > 0 {
			n2 = stack2[len(stack2)-1]
		}

		// 1. Handle Nil/Empty Tree cases
		if n1 == nil && n2 == nil {
			// Should not happen if loop condition is correct, but safe pop
			if len(stack1) > 0 {
				stack1 = stack1[:len(stack1)-1]
			}
			if len(stack2) > 0 {
				stack2 = stack2[:len(stack2)-1]
			}
			continue
		}

		// If one is nil, the other is "extra content" (diff)
		if n1 == nil {
			// n2 is extra
			diffs = append(diffs, DiffRange{Start: n2.Metadata.Start, Count: n2.Metadata.Count})
			stack2 = stack2[:len(stack2)-1] // Pop n2
			// stack1 stays same (empty/nil)
			continue
		}
		if n2 == nil {
			// n1 is extra
			diffs = append(diffs, DiffRange{Start: n1.Metadata.Start, Count: n1.Metadata.Count})
			stack1 = stack1[:len(stack1)-1] // Pop n1
			// stack2 stays same
			continue
		}

		// 2. Exact Match Check (Optimization)
		if n1.Metadata == n2.Metadata && n1.Root == n2.Root {
			// Match! Pop both and continue.
			stack1 = stack1[:len(stack1)-1]
			stack2 = stack2[:len(stack2)-1]
			continue
		}

		// 3. Offset/Start Mismatch Check
		// If starts differ, the one starting earlier is "extra" until the other starts.
		if n1.Metadata.Start < n2.Metadata.Start {
			// n1 is earlier. It's a diff.
			diffs = append(diffs, DiffRange{Start: n1.Metadata.Start, Count: n1.Metadata.Count})
			stack1 = stack1[:len(stack1)-1] // Pop n1
			// Keep n2 to compare with next n1
			continue
		}
		if n2.Metadata.Start < n1.Metadata.Start {
			// n2 is earlier.
			diffs = append(diffs, DiffRange{Start: n2.Metadata.Start, Count: n2.Metadata.Count})
			stack2 = stack2[:len(stack2)-1] // Pop n2
			// Keep n1
			continue
		}

		// 4. Starts Match: Breakdown Logic (Size priority)
		// If one is larger, break it down to see if its children partial-match the other.
		if n1.Metadata.Count > n2.Metadata.Count {
			if n1.HasData {
				// Leaf vs (Smaller) Internal/Leaf?
				// Actually if n1 is Leaf and Larger, it cannot be broken down.
				// And since starts match, n2 is a subset of n1 range.
				// n1 says "I am a single block/chunk covering X". n2 says "I am smaller X-epsilon".
				// Structure incompatible.
				diffs = append(diffs, DiffRange{Start: n1.Metadata.Start, Count: n1.Metadata.Count})
				stack1 = stack1[:len(stack1)-1]
				// We must also consume n2 because n1 "covered" it and more.
				// Wait, if n1 covers [100..200] and n2 covers [100..150].
				// We marked [100..200] as diff.
				// We should consume n2 as well so we don't double count or compare n2 with n1-next.
				// n2 is "part of" the diff we just recorded.
				stack2 = stack2[:len(stack2)-1]
				continue
			}

			// Break down n1
			stack1 = stack1[:len(stack1)-1]
			// Push children in reverse order
			if n1.Right != nil {
				stack1 = append(stack1, n1.Right)
			}
			if n1.Left != nil {
				stack1 = append(stack1, n1.Left)
			}
			continue
		}

		if n2.Metadata.Count > n1.Metadata.Count {
			if n2.HasData {
				// n2 is Leaf and Larger
				diffs = append(diffs, DiffRange{Start: n2.Metadata.Start, Count: n2.Metadata.Count})
				stack2 = stack2[:len(stack2)-1]
				stack1 = stack1[:len(stack1)-1] // Consume n1 too
				continue
			}

			// Break down n2
			stack2 = stack2[:len(stack2)-1]
			if n2.Right != nil {
				stack2 = append(stack2, n2.Right)
			}
			if n2.Left != nil {
				stack2 = append(stack2, n2.Left)
			}
			continue
		}

		// 5. Sizes Match (and Starts Match), Config Different
		// If one is Leaf and other Internal -> Structural Mismatch
		// If Hash Different -> Content Mismatch
		if n1.HasData || n2.HasData {
			// Mismatching leaves or leaf-vs-node
			diffs = append(diffs, DiffRange{Start: n1.Metadata.Start, Count: n1.Metadata.Count})
			stack1 = stack1[:len(stack1)-1]
			stack2 = stack2[:len(stack2)-1]
			continue
		}

		// Both Internal, same size, different hash.
		// Break down BOTH to find sub-diffs.
		stack1 = stack1[:len(stack1)-1]
		stack2 = stack2[:len(stack2)-1]

		if n1.Right != nil {
			stack1 = append(stack1, n1.Right)
		}
		if n1.Left != nil {
			stack1 = append(stack1, n1.Left)
		}

		if n2.Right != nil {
			stack2 = append(stack2, n2.Right)
		}
		if n2.Left != nil {
			stack2 = append(stack2, n2.Left)
		}
	}

	return diffs, nil
}
