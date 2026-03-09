package rc6

import (
	"encoding/hex"
)

type RC6Algo struct {
	w int
	r int
	b int
	S []uint32
}

func InitRC6(key string) *RC6Algo {
	keyBytes := []byte(key)
	b := len(keyBytes)
	w := 32
	r := 20

	rc6 := &RC6Algo{
		w: w,
		r: r,
		b: b,
		S: make([]uint32, 2*(r+2)),
	}

	rc6.keySetup(keyBytes)

	return rc6
}

func (rc6 *RC6Algo) keySetup(keyBytes []byte) {
	CONST := uint32(0xb7e15163)

	P := make([]uint32, 44)
	Q := make([]uint32, 44)

	for i := 1; i <= 44; i++ {
		P[i-1] = uint32(0xb7e15163) + uint32(i*2-2)
		Q[i-1] = uint32(0x5618bb1b) + uint32(i*2-1)
	}

	Lsize := (rc6.b + 3) / 4
	L := make([]uint32, Lsize)
	for i := 0; i < rc6.b; i++ {
		L[i/4] = L[i/4] + uint32(keyBytes[i])<<(8*(i%4))
	}

	rc6.S[0] = CONST
	for i := 1; i < 2*(rc6.r+2); i++ {
		rc6.S[i] = rc6.S[i-1] + P[31]
	}

	A := uint32(0)
	B := uint32(0)
	v := 3 * max(2*(rc6.r+2), Lsize)

	for i := 0; i < v; i++ {
		A = rotl(rc6.S[i%(2*(rc6.r+2))]+A+B, 3)
		B = rotl(L[i%Lsize]+A+B, int((A+B)%32))
		rc6.S[i%(2*(rc6.r+2))] = A
		L[i%Lsize] = B
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func rotl(val uint32, shift int) uint32 {
	shift = shift % 32
	if shift == 0 {
		return val
	}
	return (val << shift) | (val >> (32 - shift))
}

func rotr(val uint32, shift int) uint32 {
	shift = shift % 32
	if shift == 0 {
		return val
	}
	return (val >> shift) | (val << (32 - shift))
}

func (rc6 *RC6Algo) encryptBlock(block []byte) []byte {
	A := uint32(block[0]) | uint32(block[1])<<8 | uint32(block[2])<<16 | uint32(block[3])<<24
	B := uint32(block[4]) | uint32(block[5])<<8 | uint32(block[6])<<16 | uint32(block[7])<<24
	C := uint32(block[8]) | uint32(block[9])<<8 | uint32(block[10])<<16 | uint32(block[11])<<24
	D := uint32(block[12]) | uint32(block[13])<<8 | uint32(block[14])<<16 | uint32(block[15])<<24

	B = B + rc6.S[0]
	D = D + rc6.S[1]

	for i := 1; i <= rc6.r; i++ {
		t := rotl(B*(2*B+1), 5)
		u := rotl(D*(2*D+1), 5)
		A = rotl(A^t, int(u)) + rc6.S[2*i]
		C = rotl(C^u, int(t)) + rc6.S[2*i+1]

		A, B, C, D = B, C, D, A

		C = C + rc6.S[2*i]
		A = A + rc6.S[2*i+1]
		D = D + rc6.S[2*i+2]
		B = B + rc6.S[2*i+3]
	}

	result := make([]byte, 16)
	result[0] = byte(A)
	result[1] = byte(A >> 8)
	result[2] = byte(A >> 16)
	result[3] = byte(A >> 24)
	result[4] = byte(B)
	result[5] = byte(B >> 8)
	result[6] = byte(B >> 16)
	result[7] = byte(B >> 24)
	result[8] = byte(C)
	result[9] = byte(C >> 8)
	result[10] = byte(C >> 16)
	result[11] = byte(C >> 24)
	result[12] = byte(D)
	result[13] = byte(D >> 8)
	result[14] = byte(D >> 16)
	result[15] = byte(D >> 24)

	return result
}

func (rc6 *RC6Algo) decryptBlock(block []byte) []byte {
	A := uint32(block[0]) | uint32(block[1])<<8 | uint32(block[2])<<16 | uint32(block[3])<<24
	B := uint32(block[4]) | uint32(block[5])<<8 | uint32(block[6])<<16 | uint32(block[7])<<24
	C := uint32(block[8]) | uint32(block[9])<<8 | uint32(block[10])<<16 | uint32(block[11])<<24
	D := uint32(block[12]) | uint32(block[13])<<8 | uint32(block[14])<<16 | uint32(block[15])<<24

	D = D - rc6.S[2*rc6.r+3]
	B = B - rc6.S[2*rc6.r+2]

	for i := rc6.r; i >= 1; i-- {
		t := rotl(B*(2*B+1), 5)
		u := rotl(D*(2*D+1), 5)

		A, B, C, D = D, A, B, C

		C = rotr(C-rc6.S[2*i+1], int(t)) ^ u
		A = rotr(A-rc6.S[2*i], int(u)) ^ t

		C = C - rc6.S[2*i]
		A = A - rc6.S[2*i-1]
		D = D - rc6.S[2*i-2]
		B = B - rc6.S[2*i-3]
	}

	D = D - rc6.S[1]
	B = B - rc6.S[0]

	result := make([]byte, 16)
	result[0] = byte(A)
	result[1] = byte(A >> 8)
	result[2] = byte(A >> 16)
	result[3] = byte(A >> 24)
	result[4] = byte(B)
	result[5] = byte(B >> 8)
	result[6] = byte(B >> 16)
	result[7] = byte(B >> 24)
	result[8] = byte(C)
	result[9] = byte(C >> 8)
	result[10] = byte(C >> 16)
	result[11] = byte(C >> 24)
	result[12] = byte(D)
	result[13] = byte(D >> 8)
	result[14] = byte(D >> 16)
	result[15] = byte(D >> 24)

	return result
}

func (rc6 *RC6Algo) Encrypt(plaintext string) string {
	padding := 16 - (len(plaintext) % 16)
	for i := 0; i < padding; i++ {
		plaintext += string(byte(padding))
	}

	var result []byte
	for i := 0; i < len(plaintext); i += 16 {
		block := []byte(plaintext[i : i+16])
		encrypted := rc6.encryptBlock(block)
		result = append(result, encrypted...)
	}

	return hex.EncodeToString(result)
}

func (rc6 *RC6Algo) Decrypt(ciphertext string) string {
	decoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "Invalid ciphertext"
	}

	var result []byte
	for i := 0; i < len(decoded); i += 16 {
		block := decoded[i : i+16]
		decrypted := rc6.decryptBlock(block)
		result = append(result, decrypted...)
	}

	padding := int(result[len(result)-1])
	if padding > 0 && padding <= 16 {
		result = result[:len(result)-padding]
	}

	return string(result)
}
