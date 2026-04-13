package didindex

import "encoding/binary"

// Marshal encodes all nonces in idx as a sorted flat binary stream —
// 8 bytes per nonce, big-endian. This is the common wire format used for
// compression and decompression benchmarks.
func Marshal(idx DIDIndex) []byte {
	buf := make([]byte, idx.Len()*8)
	i := 0
	idx.Iter(func(n uint64) {
		binary.BigEndian.PutUint64(buf[i:], n)
		i += 8
	})
	return buf
}

// Unmarshal loads nonces from a flat binary stream (produced by Marshal) into idx.
func Unmarshal(idx DIDIndex, data []byte) {
	for i := 0; i+8 <= len(data); i += 8 {
		idx.Insert(binary.BigEndian.Uint64(data[i:]))
	}
}
