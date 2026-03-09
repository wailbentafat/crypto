package aes

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

type AESAlgo struct {
	roundKeys [][]byte
	nRounds   int
}

var sBox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var invSBox [256]byte

func init() {
	for i := 0; i < 256; i++ {
		invSBox[sBox[i]] = byte(i)
	}
}

var rcon = []byte{
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
}

func InitAES(key string) (*AESAlgo, error) {
	keyLen := len(key)
	var nk, nr int

	switch keyLen {
	case 16:
		nk, nr = 4, 10
	case 24:
		nk, nr = 6, 12
	case 32:
		nk, nr = 8, 14
	default:
		return nil, errors.New("key must be 16, 24, or 32 bytes")
	}

	aes := &AESAlgo{
		roundKeys: make([][]byte, (nr+1)*4),
		nRounds:   nr,
	}

	keyBytes := []byte(key)
	for i := 0; i < nk; i++ {
		aes.roundKeys[i] = keyBytes[i*4 : i*4+4]
	}

	for i := nk; i < 4*(nr+1); i++ {
		temp := make([]byte, 4)
		copy(temp, aes.roundKeys[i-1])

		if i%nk == 0 {
			temp = rotWord(temp)
			temp = subWord(temp)
			temp[0] ^= rcon[i/nk-1]
		} else if nk > 6 && i%nk == 4 {
			temp = subWord(temp)
		}

		aes.roundKeys[i] = xorBytes(aes.roundKeys[i-nk], temp)
	}

	return aes, nil
}

func rotWord(word []byte) []byte {
	return []byte{word[1], word[2], word[3], word[0]}
}

func subWord(word []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = sBox[word[i]]
	}
	return result
}

func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func (a *AESAlgo) subBytes(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = sBox[state[i][j]]
		}
	}
}

func (a *AESAlgo) invSubBytes(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = invSBox[state[i][j]]
		}
	}
}

func (a *AESAlgo) shiftRows(state [][]byte) {
	state[1][1], state[1][2], state[1][3], state[1][0] = state[1][0], state[1][1], state[1][2], state[1][3]
	state[2][2], state[2][3], state[2][0], state[2][1] = state[2][0], state[2][1], state[2][2], state[2][3]
	state[3][3], state[3][0], state[3][1], state[3][2] = state[3][0], state[3][1], state[3][2], state[3][3]
}

func (a *AESAlgo) invShiftRows(state [][]byte) {
	state[1][1], state[1][2], state[1][3], state[1][0] = state[1][3], state[1][0], state[1][1], state[1][2]
	state[2][2], state[2][3], state[2][0], state[2][1] = state[2][1], state[2][2], state[2][3], state[2][0]
	state[3][3], state[3][0], state[3][1], state[3][2] = state[3][2], state[3][3], state[3][0], state[3][1]
}

func gfMul(a, b byte) byte {
	var result byte
	for b != 0 {
		if b&1 != 0 {
			result ^= a
		}
		hiBitSet := a&0x80 != 0
		a <<= 1
		if hiBitSet {
			a ^= 0x1b
		}
		b >>= 1
	}
	return result
}

func (a *AESAlgo) mixColumns(state [][]byte) {
	for col := 0; col < 4; col++ {
		s0 := state[0][col]
		s1 := state[1][col]
		s2 := state[2][col]
		s3 := state[3][col]

		state[0][col] = gfMul(s0, 2) ^ gfMul(s1, 3) ^ s2 ^ s3
		state[1][col] = s0 ^ gfMul(s1, 2) ^ gfMul(s2, 3) ^ s3
		state[2][col] = s0 ^ s1 ^ gfMul(s2, 2) ^ gfMul(s3, 3)
		state[3][col] = gfMul(s0, 3) ^ s1 ^ s2 ^ gfMul(s3, 2)
	}
}

func (a *AESAlgo) invMixColumns(state [][]byte) {
	for col := 0; col < 4; col++ {
		s0 := state[0][col]
		s1 := state[1][col]
		s2 := state[2][col]
		s3 := state[3][col]

		state[0][col] = gfMul(s0, 0x0e) ^ gfMul(s1, 0x0b) ^ gfMul(s2, 0x0d) ^ gfMul(s3, 0x09)
		state[1][col] = gfMul(s0, 0x09) ^ gfMul(s1, 0x0e) ^ gfMul(s2, 0x0b) ^ gfMul(s3, 0x0d)
		state[2][col] = gfMul(s0, 0x0d) ^ gfMul(s1, 0x09) ^ gfMul(s2, 0x0e) ^ gfMul(s3, 0x0b)
		state[3][col] = gfMul(s0, 0x0b) ^ gfMul(s1, 0x0d) ^ gfMul(s2, 0x09) ^ gfMul(s3, 0x0e)
	}
}

func (a *AESAlgo) addRoundKey(state [][]byte, round int) {
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			state[row][col] ^= a.roundKeys[round*4+col][row]
		}
	}
}

func (a *AESAlgo) encryptBlock(block []byte) []byte {
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = make([]byte, 4)
		for j := 0; j < 4; j++ {
			state[i][j] = block[j*4+i]
		}
	}

	a.addRoundKey(state, 0)

	for round := 1; round < a.nRounds; round++ {
		a.subBytes(state)
		a.shiftRows(state)
		a.mixColumns(state)
		a.addRoundKey(state, round)
	}

	a.subBytes(state)
	a.shiftRows(state)
	a.addRoundKey(state, a.nRounds)

	result := make([]byte, 16)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			result[j*4+i] = state[i][j]
		}
	}

	return result
}

func (a *AESAlgo) decryptBlock(block []byte) []byte {
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = make([]byte, 4)
		for j := 0; j < 4; j++ {
			state[i][j] = block[j*4+i]
		}
	}

	a.addRoundKey(state, a.nRounds)

	for round := a.nRounds - 1; round >= 1; round-- {
		a.invShiftRows(state)
		a.invSubBytes(state)
		a.addRoundKey(state, round)
		a.invMixColumns(state)
	}

	a.invShiftRows(state)
	a.invSubBytes(state)
	a.addRoundKey(state, 0)

	result := make([]byte, 16)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			result[j*4+i] = state[i][j]
		}
	}

	return result
}

func (a *AESAlgo) Encrypt(plaintext string) string {
	padding := 16 - (len(plaintext) % 16)
	plaintextBytes := []byte(plaintext)
	plaintextBytes = append(plaintextBytes, bytes.Repeat([]byte{byte(padding)}, padding)...)

	var result []byte
	for i := 0; i < len(plaintextBytes); i += 16 {
		block := plaintextBytes[i : i+16]
		encrypted := a.encryptBlock(block)
		result = append(result, encrypted...)
	}

	return hex.EncodeToString(result)
}

func (a *AESAlgo) Decrypt(ciphertext string) string {
	decoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "Invalid ciphertext"
	}

	var result []byte
	for i := 0; i < len(decoded); i += 16 {
		block := decoded[i : i+16]
		decrypted := a.decryptBlock(block)
		result = append(result, decrypted...)
	}

	padding := int(result[len(result)-1])
	if padding > 0 && padding <= 16 {
		result = result[:len(result)-padding]
	}

	return string(result)
}

func main() {
	aes, _ := InitAES("mysecretkey12345")
	enc := aes.Encrypt("hello world")
	fmt.Println(enc)
	fmt.Println(aes.Decrypt(enc))
}
