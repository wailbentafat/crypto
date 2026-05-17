package modes

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

type BlockMode interface {
	Encrypt(plaintext, key []byte) ([]byte, error)
	Decrypt(ciphertext, key []byte) ([]byte, error)
}

type ECB struct {
	blockSize int
}

type CBC struct {
	blockSize int
	iv        []byte
}

type CTR struct {
	blockSize int
	nonce     []byte
}

func NewECB() *ECB {
	return &ECB{blockSize: 16}
}

func (e *ECB) Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = pkcs7Padding(plaintext, e.blockSize)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += e.blockSize {
		block.Encrypt(ciphertext[i:i+e.blockSize], plaintext[i:i+e.blockSize])
	}

	return ciphertext, nil
}

func (e *ECB) Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%e.blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += e.blockSize {
		block.Decrypt(plaintext[i:i+e.blockSize], ciphertext[i:i+e.blockSize])
	}

	plaintext = pkcs7Unpadding(plaintext)
	return plaintext, nil
}

func NewCBC(iv []byte) *CBC {
	if len(iv) == 0 {
		iv = make([]byte, 16)
		rand.Seed(time.Now().UnixNano())
		rand.Read(iv)
	}
	return &CBC{blockSize: 16, iv: iv}
}

func (c *CBC) Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = pkcs7Padding(plaintext, c.blockSize)

	ciphertext := make([]byte, len(plaintext)+len(c.iv))
	copy(ciphertext, c.iv)

	prevBlock := c.iv
	for i := 0; i < len(plaintext); i += c.blockSize {
		xored := make([]byte, c.blockSize)
		for j := 0; j < c.blockSize; j++ {
			xored[j] = plaintext[i+j] ^ prevBlock[j]
		}
		block.Encrypt(ciphertext[len(c.iv)+i:len(c.iv)+i+c.blockSize], xored)
		prevBlock = ciphertext[len(c.iv)+i : len(c.iv)+i+c.blockSize]
	}

	return ciphertext[len(c.iv):], nil
}

func (c *CBC) Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%c.blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += c.blockSize {
		decrypted := make([]byte, c.blockSize)
		block.Decrypt(decrypted, ciphertext[i:i+c.blockSize])

		var prevBlock []byte
		if i == 0 {
			prevBlock = c.iv
		} else {
			prevBlock = ciphertext[i-c.blockSize : i]
		}

		for j := 0; j < c.blockSize; j++ {
			plaintext[i+j] = decrypted[j] ^ prevBlock[j]
		}
	}

	plaintext = pkcs7Unpadding(plaintext)
	return plaintext, nil
}

func (c *CBC) GetIV() string {
	return hex.EncodeToString(c.iv)
}

func NewCTR(nonce []byte) *CTR {
	if len(nonce) == 0 {
		nonce = make([]byte, 8)
		rand.Seed(time.Now().UnixNano())
		rand.Read(nonce)
	}
	return &CTR{blockSize: 16, nonce: nonce}
}

func (c *CTR) Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += c.blockSize {
		counter := make([]byte, 16)
		copy(counter, c.nonce)
		b := make([]byte, 8)
		b[7] = byte(i / c.blockSize)
		copy(counter[8:], b)

		keystream := make([]byte, c.blockSize)
		block.Encrypt(keystream, counter)

		blocksize := c.blockSize
		if i+blocksize > len(plaintext) {
			blocksize = len(plaintext) - i
		}
		for j := 0; j < blocksize; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ keystream[j]
		}
	}

	return ciphertext, nil
}

func (c *CTR) Decrypt(ciphertext, key []byte) ([]byte, error) {
	return c.Encrypt(ciphertext, key)
}

func (c *CTR) GetNonce() string {
	return hex.EncodeToString(c.nonce)
}

func (c *CTR) SetNonce(nonceHex string) error {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return err
	}
	if len(nonce) != 8 {
		return fmt.Errorf("nonce must be 8 bytes")
	}
	c.nonce = nonce
	return nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func pkcs7Unpadding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return data
	}
	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return data
		}
	}
	return data[:len(data)-padding]
}

func CompareCiphertexts(c1, c2 []byte) float64 {
	if len(c1) != len(c2) {
		return 0
	}

	diffBits := 0
	totalBits := len(c1) * 8

	for i := 0; i < len(c1); i++ {
		xor := c1[i] ^ c2[i]
		for xor > 0 {
			if xor&1 == 1 {
				diffBits++
			}
			xor >>= 1
		}
	}

	return float64(diffBits) / float64(totalBits) * 100
}

func CBCAvalancheTest(key, iv []byte) []BlockAvalancheResult {
	original := make([]byte, 16)
	rand.Read(original)

	cbc := NewCBC(iv)
	cipher1, _ := cbc.Encrypt(original, key)

	modified := make([]byte, 16)
	copy(modified, original)
	modified[0] ^= 1

	cipher2, _ := cbc.Encrypt(modified, key)

	var results []BlockAvalancheResult
	for i := 0; i < len(cipher1)/16; i++ {
		block1 := cipher1[i*16 : (i+1)*16]
		block2 := cipher2[i*16 : (i+1)*16]

		diffBits := 0
		for j := 0; j < 16; j++ {
			xor := block1[j] ^ block2[j]
			for xor > 0 {
				if xor&1 == 1 {
					diffBits++
				}
				xor >>= 1
			}
		}

		results = append(results, BlockAvalancheResult{
			BlockIndex:  i,
			TotalBits:   128,
			DiffBits:    diffBits,
			DiffPercent: float64(diffBits) / 128.0 * 100,
		})
	}

	return results
}

type BlockAvalancheResult struct {
	BlockIndex  int
	TotalBits   int
	DiffBits    int
	DiffPercent float64
}