package benchmark

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"runtime"
	"time"
)

type HashBenchmark struct {
	Algorithm string
	DataSize  int
	TimeMs    float64
	Throughput float64
}

type CryptoBenchmark struct {
	Algorithm   string
	KeySize     int
	DataSize    int
	EncryptMs   float64
	DecryptMs   float64
	Throughput float64
}

type AESBenchmark struct {
	KeySize    int
	Mode       string
	DataSize   int
	EncryptMs  float64
	DecryptMs  float64
}

func RunHashBenchmark(dataSize int) []HashBenchmark {
	results := []HashBenchmark{}

	data := make([]byte, dataSize)
	rand.Read(data)

	md5Result := runSingleHashBenchmark("MD5", md5.New(), data)
	results = append(results, md5Result)

	sha256Result := runSingleHashBenchmark("SHA-256", sha256.New(), data)
	results = append(results, sha256Result)

	sha512Result := runSingleHashBenchmark("SHA-512", sha512.New(), data)
	results = append(results, sha512Result)

	return results
}

func runSingleHashBenchmark(name string, h hash.Hash, data []byte) HashBenchmark {
	start := time.Now()

	iterations := 1000
	for i := 0; i < iterations; i++ {
		h.Reset()
		h.Write(data)
		h.Sum(nil)
	}

	elapsed := time.Since(start)

	return HashBenchmark{
		Algorithm:   name,
		DataSize:    len(data),
		TimeMs:      elapsed.Seconds() * 1000 / float64(iterations),
		Throughput:  float64(len(data) * iterations) / elapsed.Seconds() / 1024 / 1024,
	}
}

func RunCryptoBenchmark(dataSize, keySize int) []CryptoBenchmark {
	results := []CryptoBenchmark{}

	key := make([]byte, keySize/8)
	rand.Read(key)

	data := make([]byte, dataSize)
	rand.Read(data)

	desResult := runBlockCipherBenchmark("DES", key[:8], data)
	results = append(results, desResult)

	aes128Result := runBlockCipherBenchmark("AES-128", key[:16], data)
	results = append(results, aes128Result)

	aes256Result := runBlockCipherBenchmark("AES-256", key[:32], data)
	results = append(results, aes256Result)

	return results
}

func runBlockCipherBenchmark(name string, key, data []byte) CryptoBenchmark {
	block, _ := aes.NewCipher(key)

	iterations := 10000
	data = padToBlockSize(data, block.BlockSize())

	start := time.Now()
	for i := 0; i < iterations; i++ {
		block.Encrypt(data, data)
	}
	encryptTime := time.Since(start)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		block.Decrypt(data, data)
	}
	decryptTime := time.Since(start)

	return CryptoBenchmark{
		Algorithm:   name,
		KeySize:     len(key) * 8,
		DataSize:    len(data),
		EncryptMs:   encryptTime.Seconds() * 1000 / float64(iterations),
		DecryptMs:   decryptTime.Seconds() * 1000 / float64(iterations),
		Throughput:  float64(len(data) * iterations) / encryptTime.Seconds() / 1024 / 1024,
	}
}

func padToBlockSize(data []byte, blockSize int) []byte {
	if len(data)%blockSize == 0 {
		return data
	}
	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	return padded
}

func RunAESModesBenchmark(dataSize int) []AESBenchmark {
	results := []AESBenchmark{}

	key16 := make([]byte, 16)
	key32 := make([]byte, 32)
	rand.Read(key16)
	rand.Read(key32)

	data := make([]byte, dataSize)
	rand.Read(data)

	block16, _ := aes.NewCipher(key16)
	block32, _ := aes.NewCipher(key32)

	iv := make([]byte, 16)
	rand.Read(iv)

	ecbEncTime, ecbDecTime := benchmarkECB(block16, data, 10000)
	results = append(results, AESBenchmark{
		KeySize:   128,
		Mode:      "ECB",
		DataSize:  dataSize,
		EncryptMs: ecbEncTime,
		DecryptMs: ecbDecTime,
	})

	cbcEncTime, cbcDecTime := benchmarkCBC(block32, iv, data, 10000)
	results = append(results, AESBenchmark{
		KeySize:    256,
		Mode:       "CBC",
		DataSize:   dataSize,
		EncryptMs:  cbcEncTime,
		DecryptMs:  cbcDecTime,
	})

	ctrEncTime, ctrDecTime := benchmarkCTR(block32, data, 10000)
	results = append(results, AESBenchmark{
		KeySize:    256,
		Mode:       "CTR",
		DataSize:   dataSize,
		EncryptMs:  ctrEncTime,
		DecryptMs:  ctrDecTime,
	})

	return results
}

func benchmarkECB(block cipher.Block, data []byte, iterations int) (float64, float64) {
	paddedData := padToBlockSize(data, block.BlockSize())
	ciphertext := make([]byte, len(paddedData))

	start := time.Now()
	for i := 0; i < iterations; i++ {
		for j := 0; j < len(paddedData); j += block.BlockSize() {
			block.Encrypt(ciphertext[j:j+block.BlockSize()], paddedData[j:j+block.BlockSize()])
		}
	}
	encTime := time.Since(start)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		for j := 0; j < len(paddedData); j += block.BlockSize() {
			block.Decrypt(ciphertext[j:j+block.BlockSize()], ciphertext[j:j+block.BlockSize()])
		}
	}
	decTime := time.Since(start)

	return encTime.Seconds() * 1000 / float64(iterations),
		decTime.Seconds() * 1000 / float64(iterations)
}

func benchmarkCBC(block cipher.Block, iv, data []byte, iterations int) (float64, float64) {
	paddedData := padToBlockSize(data, block.BlockSize())
	ciphertext := make([]byte, len(paddedData))

	cbc := cipher.NewCBCEncrypter(block, iv)

	start := time.Now()
	for i := 0; i < iterations; i++ {
		copy(ciphertext, paddedData)
		cbc.CryptBlocks(ciphertext, ciphertext)
	}
	encTime := time.Since(start)

	decrypter := cipher.NewCBCDecrypter(block, iv)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		decrypter.CryptBlocks(ciphertext, ciphertext)
	}
	decTime := time.Since(start)

	return encTime.Seconds() * 1000 / float64(iterations),
		decTime.Seconds() * 1000 / float64(iterations)
}

func benchmarkCTR(block cipher.Block, data []byte, iterations int) (float64, float64) {
	ciphertext := make([]byte, len(data))
	keystream := make([]byte, len(data))

	start := time.Now()
	for i := 0; i < iterations; i++ {
		for j := 0; j < len(data); j += block.BlockSize() {
			counter := make([]byte, block.BlockSize())
			rand.Read(counter)
			block.Encrypt(keystream[j:j+block.BlockSize()], counter)
		}
		for k := 0; k < len(data); k++ {
			ciphertext[k] = data[k] ^ keystream[k]
		}
	}
	encTime := time.Since(start)

	return encTime.Seconds() * 1000 / float64(iterations), encTime.Seconds() * 1000 / float64(iterations)
}

func RunFullComparison(dataSize int) ComparisonResult {
	results := ComparisonResult{}
	results.Hash = RunHashBenchmark(dataSize)
	results.Crypto = RunCryptoBenchmark(dataSize, 128)
	results.AES = RunAESModesBenchmark(dataSize)
	return results
}

type ComparisonResult struct {
	Hash    []HashBenchmark
	Crypto  []CryptoBenchmark
	AES     []AESBenchmark
}

func (r ComparisonResult) String() string {
	output := "=== BENCHMARK RESULTS ===\n\n"

	output += "--- Hash Functions ---\n"
	for _, h := range r.Hash {
		output += fmt.Sprintf("%s (%.1f KB): %.3f ms, %.2f MB/s\n",
			h.Algorithm, float64(h.DataSize)/1024, h.TimeMs, h.Throughput)
	}

	output += "\n--- Block Ciphers ---\n"
	for _, c := range r.Crypto {
		output += fmt.Sprintf("%s (%d-bit): enc=%.3f ms, dec=%.3f ms\n",
			c.Algorithm, c.KeySize, c.EncryptMs, c.DecryptMs)
	}

	output += "\n--- AES Modes ---\n"
	for _, a := range r.AES {
		output += fmt.Sprintf("AES-%d (%s): enc=%.3f ms\n",
			a.KeySize, a.Mode, a.EncryptMs)
	}

	return output
}

func SystemInfo() string {
	return fmt.Sprintf("CPU Cores: %d\nGo Version: %s\n", runtime.NumGoroutine(), runtime.Version())
}

var _ = hex.EncodeToString
var _ = des.NewCipher