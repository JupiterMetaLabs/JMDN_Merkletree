package hybrid

import (
	"encoding/binary"
	"fmt"
)

// NativeMarshal encodes the Hybrid index in its compact epoch+container format.
//
// Wire layout:
//
//	uint32BE         number of epochs
//	for each epoch:
//	  uint32BE       epoch key (high 32 bits of nonce)
//	  uint32BE       number of inner containers
//	  for each inner container:
//	    uint16BE     slot key (high 16 bits of low-32)
//	    uint8        type: 0=array  1=bitmap
//	    if array:
//	      uint16BE   count
//	      count×uint16BE  sorted values
//	    if bitmap:
//	      1024×uint64BE   bitmap words (8192 bytes)
func (h *Hybrid) NativeMarshal() []byte {
	if h.root == nil {
		b := make([]byte, 4)
		return b // 0 epochs
	}

	// Collect epochs
	type epochEntry struct {
		epoch uint32
		chunk *roaringChunk
	}
	var epochs []epochEntry
	h.root.walkChunks(func(ep uint32, c *roaringChunk) {
		epochs = append(epochs, epochEntry{ep, c})
	})

	buf := make([]byte, 0, 4+len(epochs)*64)
	buf = appU32(buf, uint32(len(epochs)))

	for _, e := range epochs {
		buf = appU32(buf, e.epoch)
		buf = appU32(buf, uint32(len(e.chunk.slotKeys)))

		for i, slotHi := range e.chunk.slotKeys {
			buf = appU16(buf, slotHi)
			switch c := e.chunk.containers[i].(type) {
			case *arrayInner:
				buf = append(buf, 0)
				buf = appU16(buf, uint16(len(c.vals)))
				for _, v := range c.vals {
					buf = appU16(buf, v)
				}
			case *bitmapInner:
				buf = append(buf, 1)
				for _, w := range c.bits {
					buf = appU64(buf, w)
				}
			}
		}
	}
	return buf
}

// NativeUnmarshal restores a Hybrid index from NativeMarshal output.
func (h *Hybrid) NativeUnmarshal(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("hybrid: data too short")
	}
	numEpochs := int(binary.BigEndian.Uint32(data))
	data = data[4:]

	h.root = nil
	h.size = 0

	for range numEpochs {
		if len(data) < 8 {
			return fmt.Errorf("hybrid: truncated epoch header")
		}
		epoch := binary.BigEndian.Uint32(data)
		numSlots := int(binary.BigEndian.Uint32(data[4:]))
		data = data[8:]

		chunk := &roaringChunk{}
		for range numSlots {
			if len(data) < 3 {
				return fmt.Errorf("hybrid: truncated slot header")
			}
			slotHi := binary.BigEndian.Uint16(data)
			ctype := data[2]
			data = data[3:]

			var c innerContainer
			switch ctype {
			case 0: // array
				if len(data) < 2 {
					return fmt.Errorf("hybrid: truncated array count")
				}
				count := int(binary.BigEndian.Uint16(data))
				data = data[2:]
				if len(data) < count*2 {
					return fmt.Errorf("hybrid: truncated array values")
				}
				ac := &arrayInner{vals: make([]uint16, count)}
				for j := range count {
					ac.vals[j] = binary.BigEndian.Uint16(data[j*2:])
				}
				data = data[count*2:]
				c = ac
				chunk.total += count

			case 1: // bitmap
				if len(data) < 1024*8 {
					return fmt.Errorf("hybrid: truncated bitmap")
				}
				bc := &bitmapInner{}
				for j := range 1024 {
					bc.bits[j] = binary.BigEndian.Uint64(data[j*8:])
					bc.n += popcount(bc.bits[j])
				}
				data = data[1024*8:]
				c = bc
				chunk.total += bc.n

			default:
				return fmt.Errorf("hybrid: unknown container type %d", ctype)
			}

			chunk.slotKeys = append(chunk.slotKeys, slotHi)
			chunk.containers = append(chunk.containers, c)
		}

		h.size += chunk.total
		if h.root == nil {
			h.root = &bpLeafH{}
		}
		updated, splitKey, sibling := h.root.upsert(epoch, chunk)
		if sibling != nil {
			h.root = &bpInternalH{
				seps:     []uint32{splitKey},
				children: []bpNode{updated, sibling},
			}
		} else {
			h.root = updated
		}
	}
	return nil
}

// ─── encoding helpers ─────────────────────────────────────────────────────────

func appU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func appU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func appU64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
