package hmac

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

type HMAC struct {
	key       []byte
	blockSize int
}

type HMACKey struct {
	Key         string
	Algorithm   string
	IsTruncated bool
}

func NewHMAC(key []byte) *HMAC {
	blockSize := 64

	if len(key) > blockSize {
		hash := sha256.Sum256(key)
		key = hash[:]
	}

	if len(key) < blockSize {
		paddedKey := make([]byte, blockSize)
		copy(paddedKey, key)
		key = paddedKey
	}

	return &HMAC{key: key, blockSize: blockSize}
}

func (h *HMAC) Sign(message string) string {
	ipad := make([]byte, h.blockSize)
	opad := make([]byte, h.blockSize)

	for i := 0; i < h.blockSize; i++ {
		ipad[i] = h.key[i] ^ 0x36
		opad[i] = h.key[i] ^ 0x5c
	}

	innerHash := sha256.Sum256(append(ipad, []byte(message)...))
	outerHash := sha256.Sum256(append(opad, innerHash[:]...))

	return hex.EncodeToString(outerHash[:])
}

func (h *HMAC) Verify(message, signature string) bool {
	expected := h.Sign(message)
	return expected == signature
}

func SignHMACSHA256(key, message []byte) string {
	h := NewHMAC(key)
	return h.Sign(string(message))
}

func VerifyHMACSHA256(key, message, signature []byte) bool {
	h := NewHMAC(key)
	return h.Verify(string(message), string(signature))
}

func SignHMACSHA512(key, message []byte) string {
	blockSize := 128

	if len(key) > blockSize {
		hash := sha512.Sum512(key)
		key = hash[:]
	}

	if len(key) < blockSize {
		paddedKey := make([]byte, blockSize)
		copy(paddedKey, key)
		key = paddedKey
	}

	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)

	for i := 0; i < blockSize; i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}

	innerHash := sha512.Sum512(append(ipad, message...))
	outerHash := sha512.Sum512(append(opad, innerHash[:]...))

	return hex.EncodeToString(outerHash[:])
}

func (h *HMAC) TruncatedSign(message string, bits int) string {
	fullSig := h.Sign(message)

	sigBytes, _ := hex.DecodeString(fullSig)
	bytesNeeded := bits / 8

	if bytesNeeded > len(sigBytes) {
		bytesNeeded = len(sigBytes)
	}

	return hex.EncodeToString(sigBytes[:bytesNeeded])
}

func CreateAPIKey(prefix string) APIKeyResult {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7 % 256)
	}

	h := NewHMAC(key)
	signature := h.Sign("api_request")

	return APIKeyResult{
		KeyID:      prefix + "_" + hex.EncodeToString(key[:8]),
		KeySecret:  hex.EncodeToString(key),
		SampleSign: signature[:16],
	}
}

func (h *HMAC) GetDescription() string {
	return `HMAC (Keyed-Hashing for Message Authentication):

HMAC(k, m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))

Where:
- H is a hash function (SHA-256, SHA-512)
- ipad = 0x36 repeated
- opad = 0x5C repeated

Properties:
- Provides integrity + authentication
- Keyed hash - requires secret key
- Resistant to length extension attacks
- Can truncate for space efficiency`
}

func (h *HMAC) SecurityAnalysis() string {
	return `HMAC Security:

1. Security depends on:
   - Underlying hash function
   - Key randomness and length
   - Proper key management

2. Attacks:
   - Brute force (2^n for n-bit key)
   - If hash broken, HMAC broken
   - Timing attacks on verification

3. Best practices:
   - Use 256-bit+ keys
   - Don't reuse keys for different purposes
   - Use unique IVs/nonces
   - Implement constant-time comparison`
}

type APIKeyResult struct {
	KeyID      string
	KeySecret  string
	SampleSign string
}

type HMACResult struct {
	FullSignature string
	Algorithm     string
	KeySize       int
	OutputSize    int
}

var _ = fmt.Sprintf

var _ = hex.EncodeToString