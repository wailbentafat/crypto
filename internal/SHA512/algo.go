package sha512

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

type SHA512 struct {
	h   [8]uint64
	msg []byte
}

var K = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8e8f99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804b90f8e9d, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

func InitSHA512() *SHA512 {
	s := &SHA512{}
	s.h = [8]uint64{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	return s
}

func (s *SHA512) Hash(message string) string {
	m := []byte(message)
	m = padMessage(m, 128)

	h := s.h
	for i := 0; i < len(m); i += 128 {
		block := m[i : i+128]
		h = processBlock(h, block)
	}

	result := make([]byte, 64)
	for i := 0; i < 8; i++ {
		result[i*8] = byte(h[i] >> 56)
		result[i*8+1] = byte(h[i] >> 48)
		result[i*8+2] = byte(h[i] >> 40)
		result[i*8+3] = byte(h[i] >> 32)
		result[i*8+4] = byte(h[i] >> 24)
		result[i*8+5] = byte(h[i] >> 16)
		result[i*8+6] = byte(h[i] >> 8)
		result[i*8+7] = byte(h[i])
	}

	return hex.EncodeToString(result)
}

func padMessage(msg []byte, blockSize int) []byte {
	msgLen := len(msg) * 8
	k := (blockSize - (msgLen%blockSize + 9) % blockSize) % blockSize

	padded := make([]byte, len(msg)+1+k+8)
	copy(padded, msg)
	padded[len(msg)] = 0x80

	for i := 0; i < 8; i++ {
		padded[len(padded)-1-i] = byte(msgLen >> (56 - i*8))
	}

	return padded
}

func processBlock(h [8]uint64, block []byte) [8]uint64 {
	w := make([]uint64, 80)

	for i := 0; i < 16; i++ {
		w[i] = uint64(block[i*8])<<56 | uint64(block[i*8+1])<<48 |
			uint64(block[i*8+2])<<40 | uint64(block[i*8+3])<<32 |
			uint64(block[i*8+4])<<24 | uint64(block[i*8+5])<<16 |
			uint64(block[i*8+6])<<8 | uint64(block[i*8+7])
	}

	for i := 16; i < 80; i++ {
		s0 := rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7)
		s1 := rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2] >> 6)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]

	for i := 0; i < 80; i++ {
		S1 := rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
		ch := (e & f) ^ ((^e) & g)
		temp1 := hh + S1 + ch + K[i] + w[i]
		S0 := rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := S0 + maj

		hh = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	}

	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
	h[4] += e
	h[5] += f
	h[6] += g
	h[7] += hh

	return h
}

func rotr64(x uint64, n int) uint64 {
	return (x >> n) | (x << (64 - n))
}

func (s *SHA512) GetInfo() string {
	return "SHA-512: 512-bit hash, 80 rounds, 64-bit words, Merkle-Damgård construction"
}

func CompareHashes(md5Hash, sha256Hash, sha512Hash string) HashComparison {
	return HashComparison{
		MD5_Length:   len(md5Hash) * 4,
		SHA256_Length: len(sha256Hash) * 4,
		SHA512_Length: len(sha512Hash) * 4,
		Ratio:        "SHA-512 output is 4x larger than SHA-256, 16x larger than MD5",
	}
}

type HashComparison struct {
	MD5_Length     int
	SHA256_Length  int
	SHA512_Length  int
	Ratio          string
}

func ValidateTestVectors() []bool {
	sha512 := InitSHA512()

	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d37a219a0d3e013b91b1fdbd75a57c4b1a5e1e5e5e5e5e5e5e5e5e5e"},
		{"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
	}

	results := make([]bool, len(tests))
	for i, test := range tests {
		result := sha512.Hash(test.input)
		results[i] = result == test.expected
	}

	return results
}

func (s *SHA512) AnalyzeAvalanche(input string) AvalancheResult {
	h1 := s.Hash(input)

	modified := []byte(input)
	if len(modified) > 0 {
		modified[0] ^= 1
	}
	h2 := s.Hash(string(modified))

	bitsDifferent := 0
	h1Bytes, _ := hex.DecodeString(h1)
	h2Bytes, _ := hex.DecodeString(h2)

	for i := 0; i < len(h1Bytes); i++ {
		xor := h1Bytes[i] ^ h2Bytes[i]
		for xor > 0 {
			if xor&1 == 1 {
				bitsDifferent++
			}
			xor >>= 1
		}
	}

	totalBits := 512
	percentage := float64(bitsDifferent) / float64(totalBits) * 100

	return AvalancheResult{
		OriginalHash:     h1,
		ModifiedHash:     h2,
		TotalBits:        totalBits,
		DifferentBits:    bitsDifferent,
		DifferentPercent: percentage,
	}
}

type AvalancheResult struct {
	OriginalHash     string
	ModifiedHash     string
	TotalBits        int
	DifferentBits    int
	DifferentPercent float64
}

var _ = fmt.Sprintf

var _ = big.NewInt