package tests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/JupiterMetaLabs/JMDN_Merkletree/merkletree"
)

// NetworkPayload simulates the JSON message sent over the wire.
type NetworkPayload struct {
	TotalBlocks uint64 `json:"total_blocks"`
	Merkleroot string `json:"merkleroot"`
	Snapshot    string `json:"snapshot_base64"` // The Merkle Tree state
}

func TestPaginationAndRestorationFlow(t *testing.T) {
	// Configuration
	totalPages := 100
	hashesPerPage := 1000
	totalHashes := totalPages * hashesPerPage

	// Use dynamic 0.5% block merge logic
	// For 100k blocks, 0.5% = 500.
	cfg := merkletree.Config{
		ExpectedTotal: uint64(totalHashes), // This triggers the 0.5% auto-calc
	}

	// ---------------------------------------------------------
	// 1. SENDER: Construct Tree from Pages
	// ---------------------------------------------------------
	fmt.Printf("[Sender] Processing %d pages (%d blocks total)...\n", totalPages, totalHashes)

	senderBuilder, err := merkletree.NewBuilder(cfg)
	if err != nil {
		t.Fatalf("Sender init failed: %v", err)
	}

	// Simulate "GetPage" loop
	allSourceHashes := make([]merkletree.Hash32, 0, totalHashes)
	for p := 0; p < totalPages; p++ {
		// Generate 1000 hashes for this page
		pageHashes := make([]merkletree.Hash32, hashesPerPage)
		for i := 0; i < hashesPerPage; i++ {
			// Mock data: just simple bytes based on index
			globalIndex := p*hashesPerPage + i
			pageHashes[i] = mockHash(globalIndex)
		}

		// Keep a copy for verification later
		allSourceHashes = append(allSourceHashes, pageHashes...)

		// Push to Merkle Builder
		// Note: We can pass 0 as startHeight if we aren't enforcing specific ranges per push,
		// or better, simulate accurate height tracking.
		startHeight := uint64(p * hashesPerPage)
		if _, err := senderBuilder.Push(startHeight, pageHashes); err != nil {
			t.Fatalf("Page %d push failed: %v", p, err)
		}
	}

	senderRoot, _ := senderBuilder.Finalize()
	fmt.Printf("[Sender] Root: %x\n", senderRoot[:4])

	// ---------------------------------------------------------
	// 2. SENDER: Serialize to JSON
	// ---------------------------------------------------------
	snapshotBytes, err := senderBuilder.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	payload := NetworkPayload{
		TotalBlocks: uint64(totalHashes),
		Merkleroot:  string(senderRoot[:]),
		Snapshot:    base64.StdEncoding.EncodeToString(snapshotBytes),
	}

	jsonBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	fmt.Printf("[Network] Transporting JSON payload (%d bytes)...\n", len(jsonBytes))

	// User Request: Save to file for inspection
	if err := os.WriteFile("payload.json", jsonBytes, 0644); err != nil {
		t.Fatalf("Failed to write payload.json: %v", err)
	}
	fmt.Println("[File] Saved payload to test/payload.json")

	// ---------------------------------------------------------
	// 3. RECEIVER: Deserialize and Reconstruct
	// ---------------------------------------------------------
	var received NetworkPayload
	if err := json.Unmarshal(jsonBytes, &received); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	decodedSnapshot, err := base64.StdEncoding.DecodeString(received.Snapshot)
	if err != nil {
		t.Fatalf("Base64 decode failed: %v", err)
	}

	// Important: Receiver must initialize compatible config
	receiverCfg := merkletree.Config{
		// Need to use same logic for BlockMerge.
		// If we don't know expectedTotal, we rely on the implementation
		// to possibly recover or we must signal it.
		// But Wait! The Snapshot actually STORES the BlockMerge value used.
		// The `Restore` function checks if our config matches.
		// To be safe, let's use the explicit BlockMerge derived from Sender logic,
		// or just 0 and let NewBuilder default, but we should ensure it matches.
		// Since 100k -> 0.5% = 500.
		// If we set ExpectedTotal here too, it works.
		ExpectedTotal: received.TotalBlocks,
	}

	receiverBuilder, err := merkletree.NewBuilder(receiverCfg)
	if err != nil {
		t.Fatalf("Receiver init failed: %v", err)
	}

	if err := receiverBuilder.Restore(decodedSnapshot); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	receiverRoot, _ := receiverBuilder.Finalize()
	fmt.Printf("[Receiver] Root: %x\n", receiverRoot[:4])

	// ---------------------------------------------------------
	// 4. VERIFICATION
	// ---------------------------------------------------------
	if senderRoot != receiverRoot {
		t.Fatalf("Root Mismatch!\nSender:   %x\nReceiver: %x", senderRoot, receiverRoot)
	}
	fmt.Println("[Success] Sender and Receiver roots match.")

	// Verify Receiver is "Live" (can append more data)
	// Let's add one more block to both
	newBlock := mockHash(totalHashes + 1)

	senderBuilder.Push(uint64(totalHashes), []merkletree.Hash32{newBlock})
	receiverBuilder.Push(uint64(totalHashes), []merkletree.Hash32{newBlock})

	newSenderRoot, _ := senderBuilder.Finalize()
	newReceiverRoot, _ := receiverBuilder.Finalize()

	if newSenderRoot != newReceiverRoot {
		t.Fatalf("Post-Restore Append Mismatch!")
	}
	fmt.Println("[Success] Both trees updated correctly with new data.")
}

func mockHash(i int) merkletree.Hash32 {
	var h merkletree.Hash32
	// Minimal deterministic "hash" for test
	h[0] = byte(i >> 24)
	h[1] = byte(i >> 16)
	h[2] = byte(i >> 8)
	h[3] = byte(i)
	return h
}
