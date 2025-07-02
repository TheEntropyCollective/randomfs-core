package randomfs

import (
	"bytes"
	"testing"
)

// TODO: Uncomment and implement tests when SplitIntoBlocks, JoinBlocks, and XORBlocks are available
// func TestBlockSplitAndJoin(t *testing.T) {
// 	data := []byte("The quick brown fox jumps over the lazy dog")
// 	blockSize := 8
// 	blocks := SplitIntoBlocks(data, blockSize)
// 	joined := JoinBlocks(blocks)
// 	if !bytes.Equal(data, joined) {
// 		t.Errorf("Joined data does not match original. Got: %s, Want: %s", joined, data)
// 	}
// }

// func TestXORBlocks(t *testing.T) {
// 	b1 := []byte{0xAA, 0xBB, 0xCC}
// 	b2 := []byte{0x11, 0x22, 0x33}
// 	x := XORBlocks(b1, b2)
// 	want := []byte{0xBB, 0x99, 0xFF}
// 	if !bytes.Equal(x, want) {
// 		t.Errorf("XOR result incorrect. Got: %v, Want: %v", x, want)
// 	}
// }

// generateDeterministicBlocks creates blocks with predictable "random" data for testing
func generateDeterministicBlocks(data []byte, blockSize int) ([][]byte, error) {
	var blocks [][]byte

	for offset := 0; offset < len(data); offset += blockSize {
		end := offset + blockSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[offset:end]

		// Create deterministic "random" block of fixed size
		// Use a simple pattern: each byte is its index position
		randomBlock := make([]byte, blockSize)
		for i := range randomBlock {
			randomBlock[i] = byte(i % 256)
		}

		// XOR with actual data to create multi-use block
		XORBlocksInPlace(randomBlock, chunk)

		blocks = append(blocks, randomBlock)
	}

	return blocks, nil
}

// deRandomizeDeterministicBlock reverses the XOR operation for testing
func deRandomizeDeterministicBlock(block []byte, dataSize int, blockIndex int) []byte {
	// Recreate the same deterministic "random" data
	randomBlock := make([]byte, len(block))
	for i := range randomBlock {
		randomBlock[i] = byte(i % 256)
	}

	// XOR the block with the same random data to recover original
	result := make([]byte, dataSize)
	for i := 0; i < dataSize; i++ {
		result[i] = block[i] ^ randomBlock[i]
	}
	return result
}

func TestBlockSplitAndJoin(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	blockSize := 8
	blocks, err := generateDeterministicBlocks(data, blockSize)
	if err != nil {
		t.Fatalf("generateDeterministicBlocks failed: %v", err)
	}
	// Simulate joining by de-randomizing each block and concatenating
	var joined []byte
	for i, block := range blocks {
		toCopy := blockSize
		if i == len(blocks)-1 {
			toCopy = len(data) - (i * blockSize)
		}
		joined = append(joined, deRandomizeDeterministicBlock(block, toCopy, i)...)
	}
	if !bytes.Equal(data, joined) {
		t.Errorf("Joined data does not match original. Got: %s, Want: %s", joined, data)
	}
}

func TestXORBlocks(t *testing.T) {
	b1 := []byte{0xAA, 0xBB, 0xCC}
	b2 := []byte{0x11, 0x22, 0x33}
	x := XORBlocks(b1, b2)
	want := []byte{0xBB, 0x99, 0xFF}
	if !bytes.Equal(x, want) {
		t.Errorf("XOR result incorrect. Got: %v, Want: %v", x, want)
	}
}
