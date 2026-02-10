package merkletree

import (
	"fmt"
)

// TreeBisect compares two trees starting from their Full Root (RootNode).
// Unlike Bisect (which compares peaks), this method treats the entire structure
// as a single tree, descending into children recursively.
//
// This is useful when the trees might have different "shapes" (peak structures)
// but you still want to find the first range of data that differs.
func (b *Builder) TreeBisect(other *Builder) (start uint64, count uint32, err error) {
	root1, err := b.RootNode()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get root node for self: %w", err)
	}
	root2, err := other.RootNode()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get root node for other: %w", err)
	}

	return b.bisectIterative(root1, root2)
}

func (b *Builder) bisectIterative(root1, root2 *Node) (uint64, uint32, error) {
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

		// 1. Handle Nil/Empty Tree cases (one tree ends before the other)
		if n1 == nil { // Tree 1 ended, Tree 2 still has content
			return n2.Metadata.Start, uint32(n2.Metadata.Count), nil
		}
		if n2 == nil { // Tree 2 ended, Tree 1 still has content
			return n1.Metadata.Start, uint32(n1.Metadata.Count), nil
		}

		// 2. Exact Match Check
		if n1.Metadata == n2.Metadata && n1.Root == n2.Root {
			// Match! Pop both and continue.
			stack1 = stack1[:len(stack1)-1]
			stack2 = stack2[:len(stack2)-1]
			continue
		}

		// 3. Start Mismatch Check
		// If the comparison stream desynchronizes on Start, it's a definite mismatch.
		if n1.Metadata.Start != n2.Metadata.Start {
			return n1.Metadata.Start, uint32(n1.Metadata.Count), nil
		}

		// 4. Breakdown Logic (Size priority)
		if n1.Metadata.Count > n2.Metadata.Count {
			// n1 is larger. Try to break it down.
			if n1.HasData {
				// n1 is a leaf but larger than n2?
				// This implies local structure incompatibility.
				// Cannot break down leaf. Diff.
				return n1.Metadata.Start, uint32(n1.Metadata.Count), nil
			}

			// Break down n1
			stack1 = stack1[:len(stack1)-1]

			if n1.Right != nil {
				stack1 = append(stack1, n1.Right)
			}
			if n1.Left != nil {
				stack1 = append(stack1, n1.Left)
			}
			continue
		}

		if n2.Metadata.Count > n1.Metadata.Count {
			// n2 is larger.
			if n2.HasData {
				return n1.Metadata.Start, uint32(n1.Metadata.Count), nil
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

		// 5. Same Size, Different Hash (implied by Step 2 failing)
		// Check for leaves
		if n1.HasData || n2.HasData {
			// If one is leaf and other is not (impossible if exact size match usually, unless type diff),
			// or both leaves with diff hash.
			return n1.Metadata.Start, uint32(n1.Metadata.Count), nil
		}

		// Break down BOTH
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
		continue
	}

	// If the loop finishes, both trees were identical.
	return 0, 0, nil
}
