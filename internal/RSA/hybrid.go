package rsa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

type HybridCipher struct {
	rsa *RSAAlgo
	aes *aesCipher
}

type aesCipher struct {
	key []byte
}

func InitHybrid() *HybridCipher {
	return &HybridCipher{
		rsa: InitRSA(),
	}
}

func (h *HybridCipher) GenerateAESKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func (h *HybridCipher) Encrypt(plaintext, pubKeyFile, keyID string) (string, error) {
	aesKey := h.GenerateAESKey()

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	plainBytes := []byte(plaintext)
	padded := pkcs7Pad(plainBytes, aes.BlockSize)

	ciphertext := make([]byte, len(padded))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, padded)

	keyEnc := h.rsa.Encrypt(hex.EncodeToString(aesKey), pubKeyFile, keyID)

	result := keyEnc + ":" + hex.EncodeToString(iv) + ":" + hex.EncodeToString(ciphertext)
	return result, nil
}

func (h *HybridCipher) Decrypt(encryptedData, privKeyFile, keyID string) (string, error) {
	parts := split3(encryptedData, ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid encrypted data format")
	}

	keyEnc := parts[0]
	ivHex := parts[1]
	ciphertextHex := parts[2]

	keyPlain := h.rsa.Decrypt(keyEnc, privKeyFile, keyID)

	aesKey, err := hex.DecodeString(keyPlain)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	unpadded := pkcs7Unpad(plaintext)
	return string(unpadded), nil
}

func (h *HybridCipher) EncryptLargeFile(fileData []byte, pubKeyFile, keyID string) (HybridResult, error) {
	start := time.Now()

	aesKey := h.GenerateAESKey()

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return HybridResult{}, err
	}

	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	ciphertext := make([]byte, len(fileData))
	for i := 0; i < len(fileData); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(fileData) {
			end = len(fileData)
		}

		plainBlock := make([]byte, aes.BlockSize)
		copy(plainBlock, fileData[i:end])

		if len(plainBlock) < aes.BlockSize {
			padded := pkcs7Pad(plainBlock, aes.BlockSize)
			plainBlock = padded
		}

		encBlock := make([]byte, aes.BlockSize)
		cbc := cipher.NewCBCEncrypter(block, iv)
		cbc.CryptBlocks(encBlock, plainBlock)
		copy(ciphertext[i:i+aes.BlockSize], encBlock)
		iv = encBlock
	}

	keyEnc := h.rsa.Encrypt(hex.EncodeToString(aesKey), pubKeyFile, keyID)

	hybridTime := time.Since(start)

	pureRSAStart := time.Now()
	_ = h.rsa.Encrypt(string(fileData[:min(100, len(fileData))]), pubKeyFile, keyID)
	pureRSATime := time.Since(pureRSAStart)

	return HybridResult{
		AESKeySize:     len(aesKey),
		IVSize:         len(iv),
		CiphertextSize: len(ciphertext),
		KeyEncSize:     len(keyEnc),
		HybridTimeUs:   hybridTime.Microseconds(),
		PureRSATimeUs:  pureRSATime.Microseconds(),
		SpeedupFactor:  float64(pureRSATime.Microseconds()) / float64(hybridTime.Microseconds()),
	}, nil
}

func (h *HybridCipher) GetDescription() string {
	return `Hybrid RSA+AES Encryption:

1. Generate random 256-bit AES key
2. Encrypt data with AES-256-CBC
3. Encrypt AES key with RSA
4. Send: RSA_Encrypted_AES_Key || IV || AES_Encrypted_Data

Why hybrid?
- RSA can only encrypt data smaller than key size
- AES is 1000x+ faster than RSA for large data
- Combined: security of RSA + speed of AES`
}

type HybridResult struct {
	AESKeySize     int
	IVSize         int
	CiphertextSize int
	KeyEncSize     int
	HybridTimeUs   int64
	PureRSATimeUs  int64
	SpeedupFactor  float64
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return data
	}
	return data[:len(data)-padding]
}

func split3(s, sep string) []string {
	result := make([]string, 0)
	current := ""
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, current)
			current = ""
			i += len(sep) - 1
		} else {
			current += string(s[i])
		}
	}
	result = append(result, current)
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (h *HybridCipher) OAEPEncrypt(plaintext, pubKeyFile, keyID string) (string, error) {
	plainBytes := []byte(plaintext)

	labelHash := simpleHash("RSA-OAEP")
	_ = labelHash

	seed := make([]byte, 32)
	rand.Read(seed)

	labelBytes := labelHash.Bytes()
	db := make([]byte, len(labelBytes)+len(plainBytes)+1)
	copy(db, labelBytes)
	db[len(labelBytes)] = 0
	copy(db[len(labelBytes)+1:], plainBytes)

	dbMask := mgf1(seed, len(db))
	for i := range db {
		db[i] ^= dbMask[i]
	}

	maskedDB := db

	mgfOutput := mgf1(maskedDB[:32], len(seed))
	for i := range seed {
		seed[i] ^= mgfOutput[i]
	}

	em := append(seed, maskedDB...)

	keyEnc := h.rsa.Encrypt(hex.EncodeToString(em), pubKeyFile, keyID)

	return keyEnc, nil
}

func (h *HybridCipher) OAEPDecrypt(encrypted, privKeyFile, keyID string) (string, error) {
	keyPlain := h.rsa.Decrypt(encrypted, privKeyFile, keyID)

	emBytes, err := hex.DecodeString(keyPlain)
	if err != nil {
		return "", err
	}

	seed := emBytes[:32]
	maskedDB := emBytes[32:]

	mgfOutput := mgf1(seed, len(maskedDB))
	for i := range maskedDB {
		maskedDB[i] ^= mgfOutput[i]
	}

	labelHash := maskedDB[:32]
	_ = labelHash
	maskedDB = maskedDB[32:]

	firstZero := -1
	for i, b := range maskedDB {
		if b == 0 && firstZero == -1 {
			firstZero = i
			break
		}
	}

	if firstZero == -1 || firstZero > len(maskedDB) {
		return "", fmt.Errorf("OAEP decoding failed")
	}

	plaintext := maskedDB[firstZero+1:]
	return string(plaintext), nil
}

func mgf1(seed []byte, length int) []byte {
	result := make([]byte, length)
	counter := 0

	for i := 0; i < length; i += 32 {
		counterBytes := make([]byte, 4)
		counterBytes[0] = byte(counter >> 24)
		counterBytes[1] = byte(counter >> 16)
		counterBytes[2] = byte(counter >> 8)
		counterBytes[3] = byte(counter)

		hash := simpleHash(string(seed) + string(counterBytes))
		hashBytes := hash.Bytes()

		end := i + 32
		if end > length {
			end = length
		}
		copy(result[i:end], hashBytes[:end-i])

		counter++
	}

	return result
}

func simpleHash(s string) *big.Int {
	hash := big.NewInt(0)
	for i := range s {
		hash.Mul(hash, big.NewInt(31))
		hash.Add(hash, big.NewInt(int64(s[i])))
	}
	return hash
}

type bigInt struct{}

func (h *HybridCipher) GetTextbookRSADanger() string {
	return `Textbook RSA Vulnerabilities:

1. No padding = deterministic encryption
   E(m1) * E(m2) = E(m1*m2) mod n (multiplicative property)

2. Small e with small m: Bleichenbacher's attack
   If e=3 and m < n^(1/3), can recover m via cube root

3. No randomness = pattern leakage
   Same message always produces same ciphertext

Solution: Use OAEP (PKCS#1 v2) or PSS padding`
}