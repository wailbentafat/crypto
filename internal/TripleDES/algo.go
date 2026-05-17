package tripledes

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"time"
)

type TripleDES struct {
	cipher cipher.Block
	key1   []byte
	key2   []byte
	key3   []byte
}

func InitTripleDES(key string) (*TripleDES, error) {
	keyBytes := []byte(key)

	paddedKey := make([]byte, 24)
	copy(paddedKey, keyBytes)

	if len(keyBytes) < 24 {
		for i := len(keyBytes); i < 24; i++ {
			paddedKey[i] = keyBytes[i%len(keyBytes)]
		}
	}

	block, err := des.NewTripleDESCipher(paddedKey)
	if err != nil {
		return nil, err
	}

	return &TripleDES{
		cipher: block,
		key1:   paddedKey[:8],
		key2:   paddedKey[8:16],
		key3:   paddedKey[16:],
	}, nil
}

func (t *TripleDES) Encrypt(plaintext string) string {
	plainBytes := []byte(plaintext)

	padded := pkcs7Padding(plainBytes, t.cipher.BlockSize())

	result := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 8 {
		encrypted := t.encryptBlock(padded[i : i+8])
		copy(result[i:i+8], encrypted)
	}

	return hex.EncodeToString(result)
}

func (t *TripleDES) Decrypt(ciphertext string) string {
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return ""
	}

	result := make([]byte, len(cipherBytes))
	for i := 0; i < len(cipherBytes); i += 8 {
		decrypted := t.decryptBlock(cipherBytes[i : i+8])
		copy(result[i:i+8], decrypted)
	}

	unpadded := pkcs7Unpadding(result)
	return string(unpadded)
}

func (t *TripleDES) encryptBlock(block []byte) []byte {
	encrypted := make([]byte, 8)
	copy(encrypted, block)

	temp := make([]byte, 8)

	c1, _ := des.NewCipher(t.key1)
	c1.Encrypt(temp, encrypted)
	encrypted, temp = temp, encrypted

	c2, _ := des.NewCipher(t.key2)
	c2.Decrypt(temp, encrypted)
	encrypted, temp = temp, encrypted

	c3, _ := des.NewCipher(t.key3)
	c3.Encrypt(temp, encrypted)

	return temp
}

func (t *TripleDES) decryptBlock(block []byte) []byte {
	decrypted := make([]byte, 8)
	copy(decrypted, block)

	temp := make([]byte, 8)

	c1, _ := des.NewCipher(t.key3)
	c1.Decrypt(temp, decrypted)
	decrypted, temp = temp, decrypted

	c2, _ := des.NewCipher(t.key2)
	c2.Encrypt(temp, decrypted)
	decrypted, temp = temp, decrypted

	c3, _ := des.NewCipher(t.key1)
	c3.Encrypt(temp, decrypted)

	return temp
}

func (t *TripleDES) GetInfo() string {
	return "Triple-DES (3DES): 64-bit block, 168-bit key (3x56-bit), 48 rounds (EDE mode)"
}

func (t *TripleDES) EncryptCBC(iv, plaintext []byte) string {
	plainBytes := []byte(plaintext)
	padded := pkcs7Padding(plainBytes, 8)

	result := make([]byte, len(padded)+len(iv))
	copy(result, iv)

	prevBlock := iv
	for i := 0; i < len(padded); i += 8 {
		xored := make([]byte, 8)
		for j := 0; j < 8; j++ {
			xored[j] = padded[i+j] ^ prevBlock[j]
		}

		encrypted := t.encryptBlock(xored)
		copy(result[len(iv)+i:i+8], encrypted)
		prevBlock = result[len(iv)+i : len(iv)+i+8]
	}

	return hex.EncodeToString(result[len(iv):])
}

func BenchmarkEncryption(dataSize int, key string) BenchmarkResult {
	desKey := key
	if len(desKey) > 8 {
		desKey = desKey[:8]
	}
	for len(desKey) < 8 {
		desKey += "0"
	}

	triple, err := InitTripleDES(key)
	if err != nil {
		return BenchmarkResult{Error: err.Error()}
	}

	data := make([]byte, dataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	start := time.Now()
	_ = triple.Encrypt(string(data))
	desTime := time.Since(start).Milliseconds()

	triple2, _ := InitTripleDES(key + key[:8])
	start = time.Now()
	_ = triple2.Encrypt(string(data))
	tripleTime := time.Since(start).Milliseconds()

	return BenchmarkResult{
		DataSize:      dataSize,
		DESTimeMs:     desTime,
		TripleDESTimeMs: tripleTime,
		Ratio:         float64(tripleTime) / float64(desTime),
	}
}

type BenchmarkResult struct {
	DataSize         int
	DESTimeMs        int64
	TripleDESTimeMs  int64
	Ratio            float64
	Error            string
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
	return data[:len(data)-padding]
}

type SingleDES struct {
	cipher cipher.Block
	key    []byte
}

func InitDES(key string) (*SingleDES, error) {
	keyBytes := []byte(key)

	paddedKey := make([]byte, 8)
	copy(paddedKey, keyBytes)

	if len(keyBytes) < 8 {
		for i := len(keyBytes); i < 8; i++ {
			paddedKey[i] = keyBytes[i%len(keyBytes)]
		}
	}

	block, err := des.NewCipher(paddedKey)
	if err != nil {
		return nil, err
	}

	return &SingleDES{cipher: block, key: paddedKey}, nil
}

func (d *SingleDES) Encrypt(plaintext string) string {
	plainBytes := []byte(plaintext)
	padded := pkcs7Padding(plainBytes, 8)

	result := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 8 {
		d.cipher.Encrypt(result[i:i+8], padded[i:i+8])
	}

	return hex.EncodeToString(result)
}

func (d *SingleDES) Decrypt(ciphertext string) string {
	cipherBytes, _ := hex.DecodeString(ciphertext)

	result := make([]byte, len(cipherBytes))
	for i := 0; i < len(cipherBytes); i += 8 {
		d.cipher.Decrypt(result[i:i+8], cipherBytes[i:i+8])
	}

	return string(pkcs7Unpadding(result))
}

func CompareEncryptionModes(plaintext, key string) ModeComparison {
	result := ModeComparison{}

	des, _ := InitDES(key[:8])
	desResult := des.Encrypt(plaintext)
	result.DES_ECB = desResult

	desCBC, _ := InitDES(key[:8])
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = byte(i)
	}
	result.DES_CBC = desCBC.Encrypt(plaintext)
	result.DES_IV = hex.EncodeToString(iv)

	triple, _ := InitTripleDES(key)
	result.TripleDES_CBC = triple.EncryptCBC(iv, []byte(plaintext))

	return result
}

type ModeComparison struct {
	DES_ECB      string
	DES_CBC      string
	DES_IV       string
	TripleDES_CBC string
}