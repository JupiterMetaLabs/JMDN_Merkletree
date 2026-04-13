package roaring

import (
	"encoding/binary"
	"fmt"
)

// NativeMarshal encodes the Roaring Bitmap in its compact container format.
//
// Wire layout:
//
//	uint32BE         number of containers
//	for each container:
//	  [6]byte        high 48-bit container key
//	  uint8          type: 0=array  1=bitmap
//	  if array:
//	    uint16BE     count of uint16 values
//	    count×uint16BE  sorted values (2 bytes each vs 8 for flat uint64)
//	  if bitmap:
//	    1024×uint64BE  bitmap words (8192 bytes fixed, covers 65536 values)
//
// For 10k sequential nonces this is ~21 KB vs 78 KB flat — a 3.7× size reduction
// before any additional compression is applied.
func (r *Roaring) NativeMarshal() []byte {
	r.sortKeys()
	buf := make([]byte, 0, 4+len(r.sortedKeys)*32)
	buf = appendU32(buf, uint32(len(r.sortedKeys)))
	for _, hi := range r.sortedKeys {
		buf = appendU48(buf, hi)
		switch c := r.cm[hi].(type) {
		case *arrayContainer:
			buf = append(buf, 0)
			buf = appendU16(buf, uint16(len(c.vals)))
			for _, v := range c.vals {
				buf = appendU16(buf, v)
			}
		case *bitmapContainer:
			buf = append(buf, 1)
			for _, w := range c.bits {
				buf = appendU64(buf, w)
			}
		}
	}
	return buf
}

// NativeUnmarshal restores a Roaring Bitmap from NativeMarshal output.
func (r *Roaring) NativeUnmarshal(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("roaring: data too short")
	}
	n := int(binary.BigEndian.Uint32(data))
	data = data[4:]

	r.cm = make(map[uint64]container, n)
	r.sortedKeys = r.sortedKeys[:0]
	r.keysValid = false
	r.size = 0

	for range n {
		if len(data) < 7 {
			return fmt.Errorf("roaring: truncated container header")
		}
		hi := readU48(data)
		data = data[6:]
		ctype := data[0]
		data = data[1:]

		switch ctype {
		case 0: // array
			if len(data) < 2 {
				return fmt.Errorf("roaring: truncated array count")
			}
			count := int(binary.BigEndian.Uint16(data))
			data = data[2:]
			if len(data) < count*2 {
				return fmt.Errorf("roaring: truncated array values")
			}
			ac := &arrayContainer{vals: make([]uint16, count)}
			for j := range count {
				ac.vals[j] = binary.BigEndian.Uint16(data[j*2:])
			}
			data = data[count*2:]
			r.cm[hi] = ac
			r.size += count

		case 1: // bitmap
			if len(data) < 1024*8 {
				return fmt.Errorf("roaring: truncated bitmap")
			}
			bc := &bitmapContainer{}
			for j := range 1024 {
				bc.bits[j] = binary.BigEndian.Uint64(data[j*8:])
				bc.n += popcount64(bc.bits[j])
			}
			data = data[1024*8:]
			r.cm[hi] = bc
			r.size += bc.n

		default:
			return fmt.Errorf("roaring: unknown container type %d", ctype)
		}
	}
	return nil
}

// ─── encoding helpers ─────────────────────────────────────────────────────────

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendU48(b []byte, v uint64) []byte {
	return append(b, byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendU64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readU48(b []byte) uint64 {
	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
		uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}
