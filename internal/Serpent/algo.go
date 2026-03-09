package serpent

import (
	"encoding/hex"
)

type SerpentAlgo struct {
	key []byte
	rk  []uint32
}

var sBox = [8][16]uint8{
	{3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
	{15, 12, 2, 7, 0, 13, 5, 10, 14, 4, 9, 11, 3, 8, 1, 6},
	{1, 15, 8, 3, 12, 0, 11, 6, 10, 4, 13, 5, 14, 9, 7, 2},
	{7, 2, 14, 9, 13, 4, 1, 10, 12, 11, 0, 5, 8, 15, 6, 3},
	{5, 10, 9, 13, 2, 1, 7, 14, 4, 8, 15, 6, 11, 0, 12, 3},
	{10, 9, 13, 0, 7, 5, 11, 3, 14, 6, 4, 8, 2, 15, 12, 1},
	{11, 5, 15, 3, 10, 0, 9, 13, 14, 8, 2, 4, 6, 12, 7, 1},
	{12, 6, 11, 2, 9, 15, 1, 4, 8, 13, 3, 7, 10, 5, 0, 14},
}

func InitSerpent(key string) *SerpentAlgo {
	if len(key) < 16 {
		key = key + string(make([]byte, 16-len(key)))
	}
	key = key[:32]

	algo := &SerpentAlgo{
		key: []byte(key),
		rk:  make([]uint32, 132),
	}

	algo.keySchedule()

	return algo
}

func (s *SerpentAlgo) keySchedule() {
	var w [132]uint32

	for i := 0; i < 8; i++ {
		w[i] = uint32(s.key[4*i]) | uint32(s.key[4*i+1])<<8 | uint32(s.key[4*i+2])<<16 | uint32(s.key[4*i+3])<<24
	}

	for i := 8; i < 132; i++ {
		w[i] = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ uint32(0x9e3779b9) ^ uint32(i)
	}

	for i := 0; i < 32; i++ {
		var t uint32
		switch i % 4 {
		case 0:
			t = w[i+3]
		case 1:
			t = w[i+1]
		case 2:
			t = w[i+5]
		case 3:
			t = w[i+7]
		}

		x := uint32(sBox[i%8][byte(t>>4)])<<4 | uint32(sBox[i%8][byte(t&0x0f)])
		s.rk[4*i] = x
	}
}

func (s *SerpentAlgo) transform(block []byte, encrypt bool) []byte {
	var x [4]uint32

	for i := 0; i < 4; i++ {
		x[i] = uint32(block[4*i]) | uint32(block[4*i+1])<<8 | uint32(block[4*i+2])<<16 | uint32(block[4*i+3])<<24
	}

	if encrypt {
		for round := 0; round < 31; round++ {
			x[0] ^= s.rk[4*round]
			x[1] ^= s.rk[4*round+1]
			x[2] ^= s.rk[4*round+2]
			x[3] ^= s.rk[4*round+3]

			for i := 0; i < 4; i++ {
				y := byte(x[i] >> 4)
				z := byte(x[i] & 0x0f)
				val := uint32(sBox[round%8][y])<<4 | uint32(sBox[round%8][z])
				x[i] = val
			}

			var t0, t1, t2, t3 uint32
			t0 = (x[0] << 13) | (x[0] >> (32 - 13))
			t2 = (x[2] << 3) | (x[2] >> (32 - 3))
			t1 = x[1] ^ t0 ^ (x[3] << 3)
			t3 = x[3] ^ t2 ^ ((x[0] >> 5) ^ t0)
			x[0] = t0
			x[2] = t2
			x[1] = t1
			x[3] = t3

			var tmp uint32
			tmp = x[0]
			x[0] = x[2]
			x[2] = tmp
			tmp = x[1]
			x[1] = x[3]
			x[3] = tmp
		}

		x[0] ^= s.rk[124]
		x[1] ^= s.rk[125]
		x[2] ^= s.rk[126]
		x[3] ^= s.rk[127]
	} else {
		x[0] ^= s.rk[124]
		x[1] ^= s.rk[125]
		x[2] ^= s.rk[126]
		x[3] ^= s.rk[127]

		for round := 31; round > 0; round-- {
			var tmp uint32
			tmp = x[1]
			x[1] = x[3]
			x[3] = tmp
			tmp = x[0]
			x[0] = x[2]
			x[2] = tmp

			t0 := (x[0] << 13) | (x[0] >> (32 - 13))
			t2 := (x[2] << 3) | (x[2] >> (32 - 3))
			t1 := x[1] ^ t0 ^ (x[3] << 3)
			t3 := x[3] ^ t2 ^ ((x[0] >> 5) ^ t0)
			x[0] = t0
			x[2] = t2
			x[1] = t1
			x[3] = t3

			for i := 0; i < 4; i++ {
				inp := byte(x[i] >> 4)
				val := sBox[round%8][inp]
				inp2 := byte(x[i] & 0x0f)
				val2 := sBox[round%8][inp2]
				x[i] = uint32(val)<<4 | uint32(val2)
			}

			x[0] ^= s.rk[4*round]
			x[1] ^= s.rk[4*round+1]
			x[2] ^= s.rk[4*round+2]
			x[3] ^= s.rk[4*round+3]
		}

		x[0] ^= s.rk[0]
		x[1] ^= s.rk[1]
		x[2] ^= s.rk[2]
		x[3] ^= s.rk[3]
	}

	result := make([]byte, 16)
	for i := 0; i < 4; i++ {
		result[4*i] = byte(x[i])
		result[4*i+1] = byte(x[i] >> 8)
		result[4*i+2] = byte(x[i] >> 16)
		result[4*i+3] = byte(x[i] >> 24)
	}

	return result
}

func (s *SerpentAlgo) Encrypt(plaintext string) string {
	padding := 16 - (len(plaintext) % 16)
	for i := 0; i < padding; i++ {
		plaintext += string(byte(padding))
	}

	var result []byte
	for i := 0; i < len(plaintext); i += 16 {
		block := []byte(plaintext[i : i+16])
		encrypted := s.transform(block, true)
		result = append(result, encrypted...)
	}

	return hex.EncodeToString(result)
}

func (s *SerpentAlgo) Decrypt(ciphertext string) string {
	decoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "Invalid ciphertext"
	}

	var result []byte
	for i := 0; i < len(decoded); i += 16 {
		block := decoded[i : i+16]
		decrypted := s.transform(block, false)
		result = append(result, decrypted...)
	}

	padding := int(result[len(result)-1])
	if padding > 0 && padding <= 16 {
		result = result[:len(result)-padding]
	}

	return string(result)
}

func main() {
	s := InitSerpent("mysecretkey1234567")
	enc := s.Encrypt("hello world")
	s.Decrypt(enc)
}
