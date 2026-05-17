package bluetooth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func simpleHash(s string) []byte {
	h := make([]byte, 32)
	for i := range s {
		h[i%32] ^= byte(s[i])
	}
	return h
}

type SecureRFCOMM struct {
	bdaddr       string
	channel      int
	pin          []byte
	linkKey      []byte
	encrypted    bool
}

func InitSecureRFCOMM(bdaddr string, channel int) *SecureRFCOMM {
	return &SecureRFCOMM{
		bdaddr:   bdaddr,
		channel:  channel,
		pin:      make([]byte, 16),
		encrypted: false,
	}
}

func (b *SecureRFCOMM) SetPin(pin string) {
	b.pin = []byte(pin)
	if len(b.pin) > 16 {
		b.pin = b.pin[:16]
	}
	for len(b.pin) < 16 {
		b.pin = append(b.pin, 0)
	}
}

func (b *SecureRFCOMM) Pair() error {
	b.linkKey = b.deriveLinkKey()
	return nil
}

func (b *SecureRFCOMM) deriveLinkKey() []byte {
	key := make([]byte, 32)
	copy(key, b.pin)

	for i := 0; i < 1000; i++ {
		h := simpleHash(string(key))
		copy(key, h[:32])
	}

	return key[:16]
}

func (b *SecureRFCOMM) Connect() error {
	if b.linkKey == nil {
		return fmt.Errorf("not paired")
	}
	b.encrypted = true
	return nil
}

func (b *SecureRFCOMM) Send(message string) (string, error) {
	if !b.encrypted {
		return message, fmt.Errorf("connection not encrypted")
	}

	encrypted := b.encryptLinkLayer(message)
	return encrypted, nil
}

func (b *SecureRFCOMM) Receive(data string) (string, error) {
	if !b.encrypted {
		return data, nil
	}
	return b.decryptLinkLayer(data), nil
}

func (b *SecureRFCOMM) encryptLinkLayer(data string) string {
	block, _ := aes.NewCipher(b.linkKey)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	ciphertext := make([]byte, len(data))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, []byte(data))

	return hex.EncodeToString(iv) + hex.EncodeToString(ciphertext)
}

func (b *SecureRFCOMM) decryptLinkLayer(data string) string {
	if len(data) < 32 {
		return data
	}

	iv, _ := hex.DecodeString(data[:32])
	ciphertext, _ := hex.DecodeString(data[32:])

	block, _ := aes.NewCipher(b.linkKey)
	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	return string(plaintext)
}

func (b *SecureRFCOMM) GetSecurityLevel() string {
	return `Bluetooth Security Modes:

Mode 1 (No security):
- No authentication
- No encryption
- DISABLED for production

Mode 2 (Service level):
- Auth required per service
- Uses PIN for key derivation
- Legacy

Mode 3 (Link level):
- Auth + encrypt always on
- Stronger security
- Used for RFCOMM`
}