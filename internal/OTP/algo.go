package otp

import (
	"encoding/hex"
	"fmt"
)

type OTPAlgo struct{}

func InitOTP() *OTPAlgo {
	return &OTPAlgo{}
}

// Encrypt performs XOR between plaintext and key.
// It returns a hex-encoded string.
func (o *OTPAlgo) Encrypt(plaintext, key string) (string, error) {
	if len(plaintext) != len(key) {
		return "", fmt.Errorf("key length (%d) must match plaintext length (%d)", len(key), len(plaintext))
	}

	plaintextBytes := []byte(plaintext)
	keyBytes := []byte(key)
	result := make([]byte, len(plaintextBytes))

	for i := 0; i < len(plaintextBytes); i++ {
		result[i] = plaintextBytes[i] ^ keyBytes[i]
	}

	return hex.EncodeToString(result), nil
}

// Decrypt performs XOR between hex-encoded ciphertext and key.
func (o *OTPAlgo) Decrypt(ciphertextHex, key string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex ciphertext: %v", err)
	}

	if len(ciphertext) != len(key) {
		return "", fmt.Errorf("key length (%d) must match ciphertext length (%d)", len(key), len(ciphertext))
	}

	keyBytes := []byte(key)
	result := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i++ {
		result[i] = ciphertext[i] ^ keyBytes[i]
	}

	return string(result), nil
}

// XORCiphertexts performs XOR between two hex-encoded ciphertexts.
func (o *OTPAlgo) XORCiphertexts(c1Hex, c2Hex string) (string, error) {
	c1, err := hex.DecodeString(c1Hex)
	if err != nil {
		return "", fmt.Errorf("invalid hex ciphertext 1: %v", err)
	}
	c2, err := hex.DecodeString(c2Hex)
	if err != nil {
		return "", fmt.Errorf("invalid hex ciphertext 2: %v", err)
	}

	minLen := len(c1)
	if len(c2) < minLen {
		minLen = len(c2)
	}

	result := make([]byte, minLen)
	for i := 0; i < minLen; i++ {
		result[i] = c1[i] ^ c2[i]
	}

	return hex.EncodeToString(result), nil
}
