package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

type RSAAlgo struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func InitRSA() *RSAAlgo {
	return &RSAAlgo{}
}

func GenerateKeys(bits int) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Sprintf("Error generating keys: %v", err)
	}

	return fmt.Sprintf("Public Key (N): %s\nPublic Key (E): %d\nPrivate Key (D): %s\nPrivate Key (N): %s\n",
		privateKey.PublicKey.N.String(),
		privateKey.PublicKey.E,
		privateKey.D.String(),
		privateKey.N.String())
}

func (r *RSAAlgo) Encrypt(plaintext, pubKeyFile, keyID string) string {
	n, _ := new(big.Int).SetString(keyID, 10)
	e := 65537

	publicKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(plaintext))
	if err != nil {
		return fmt.Sprintf("Encryption error: %v", err)
	}

	return hex.EncodeToString(ciphertext)
}

func (r *RSAAlgo) Decrypt(ciphertextHex, prvKeyFile, keyID string) string {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "Invalid ciphertext"
	}

	d, _ := new(big.Int).SetString(keyID, 10)
	n, _ := new(big.Int).SetString(keyID, 10)

	privateKey := &rsa.PrivateKey{
		D: d,
		PublicKey: rsa.PublicKey{
			N: n,
			E: 65537,
		},
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return fmt.Sprintf("Decryption error: %v", err)
	}

	return string(plaintext)
}

func (r *RSAAlgo) Hash(message string) string {
	h := sha256.Sum256([]byte(message))
	return hex.EncodeToString(h[:])
}
