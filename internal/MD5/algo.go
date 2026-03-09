package md5

import (
	"encoding/hex"
	"fmt"
)

type MD5Algo struct {
	h [4]uint32
}

func initMD5() *MD5Algo {
	return &MD5Algo{
		h: [4]uint32{
			0x67452301,
			0xefcdab89,
			0x98badcfe,
			0x10325476,
		},
	}
}

func (m *MD5Algo) leftRotate(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

func (m *MD5Algo) md5Padding(message []byte) []byte {
	msgLen := uint64(len(message))
	bitLen := msgLen * 8

	padding := make([]byte, 0)
	padding = append(padding, 0x80)

	for (uint64(len(padding))+msgLen)%64 != 56 {
		padding = append(padding, 0x00)
	}

	padding = append(padding, []byte{
		byte(bitLen), byte(bitLen >> 8), byte(bitLen >> 16), byte(bitLen >> 24),
		byte(bitLen >> 32), byte(bitLen >> 40), byte(bitLen >> 48), byte(bitLen >> 56),
	}...)

	return append(message, padding...)
}

func (m *MD5Algo) processBlock(chunk []byte) {
	var a, b, c, d uint32

	a = m.h[0]
	b = m.h[1]
	c = m.h[2]
	d = m.h[3]

	x := make([]uint32, 16)
	for i := 0; i < 16; i++ {
		x[i] = uint32(chunk[i*4]) | uint32(chunk[i*4+1])<<8 | uint32(chunk[i*4+2])<<16 | uint32(chunk[i*4+3])<<24
	}

	var functions = []func(uint32, uint32, uint32) uint32{
		func(x, y, z uint32) uint32 { return (x & y) | (^x & z) },
		func(x, y, z uint32) uint32 { return (x & z) | (y & ^z) },
		func(x, y, z uint32) uint32 { return x ^ y ^ z },
		func(x, y, z uint32) uint32 { return y ^ (x | ^z) },
	}

	var shifts = []uint{7, 12, 17, 22, 5, 9, 14, 20, 4, 10, 16, 23, 6, 9, 11, 15}

	for round := 0; round < 4; round++ {
		for i := 0; i < 16; i++ {
			var k int
			switch round {
			case 0:
				k = i
			case 1:
				k = (5*i + 1) % 16
			case 2:
				k = (3*i + 5) % 16
			case 3:
				k = (7 * i) % 16
			}

			idx := round*16 + i
			f := functions[round]
			shift := shifts[i%4]

			temp := d
			d = c
			c = b
			b = b + m.leftRotate(a+f(b, c, d)+x[k]+uint32(idx), shift)
			a = temp
		}
	}

	m.h[0] += a
	m.h[1] += b
	m.h[2] += c
	m.h[3] += d
}

func Hash(message string) string {
	m := initMD5()

	padded := m.md5Padding([]byte(message))

	for i := 0; i < len(padded); i += 64 {
		m.processBlock(padded[i : i+64])
	}

	result := make([]byte, 16)
	for i := 0; i < 4; i++ {
		result[i*4] = byte(m.h[i])
		result[i*4+1] = byte(m.h[i] >> 8)
		result[i*4+2] = byte(m.h[i] >> 16)
		result[i*4+3] = byte(m.h[i] >> 24)
	}

	return hex.EncodeToString(result)
}

func main() {
	fmt.Println(Hash("hello"))
}
