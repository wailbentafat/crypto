package chat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type Message struct {
	Sender    string    `json:"sender"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Encrypted bool      `json:"encrypted"`
	MAC       string    `json:"mac,omitempty"`
}

type SecureChat struct {
	conn       *net.UDPConn
	localAddr  *net.UDPAddr
	remoteAddr *net.UDPAddr
	key        []byte
	username   string
}

func InitSecureChat(localPort, remotePort int, remoteIP, username string) (*SecureChat, error) {
	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, err
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", remoteIP, remotePort))
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	rand.Read(key)

	return &SecureChat{
		conn:       conn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		key:        key,
		username:   username,
	}, nil
}

func (c *SecureChat) SendMessage(content string) error {
	msg := Message{
		Sender:    c.username,
		Content:   content,
		Timestamp: time.Now(),
	}

	encrypted, mac := c.encryptMessage(content)
	msg.Encrypted = true
	msg.Content = encrypted
	msg.MAC = mac

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = c.conn.WriteToUDP(data, c.remoteAddr)
	return err
}

func (c *SecureChat) ReceiveMessage() (Message, error) {
	buf := make([]byte, 4096)
	n, addr, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return Message{}, err
	}

	var msg Message
	err = json.Unmarshal(buf[:n], &msg)
	if err != nil {
		return Message{}, err
	}

	if msg.Encrypted {
		content := c.decryptMessage(msg.Content)
		msg.Content = content

		if !c.verifyMAC(content, msg.MAC) {
			return Message{}, fmt.Errorf("message authentication failed")
		}
	}

	fmt.Printf("[%s] %s: %s\n", msg.Timestamp.Format("15:04"), msg.Sender, msg.Content)
	_ = addr

	return msg, nil
}

func (c *SecureChat) encryptMessage(plaintext string) (string, string) {
	block, _ := aes.NewCipher(c.key)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	ciphertext := make([]byte, len(plaintext))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, []byte(plaintext))

	encrypted := hex.EncodeToString(iv) + hex.EncodeToString(ciphertext)

	mac := computeHMAC(plaintext, c.key)

	return encrypted, mac
}

func (c *SecureChat) decryptMessage(encrypted string) string {
	ivHex := encrypted[:32]
	cipherHex := encrypted[32:]

	iv, _ := hex.DecodeString(ivHex)
	ciphertext, _ := hex.DecodeString(cipherHex)

	block, _ := aes.NewCipher(c.key)
	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	return string(plaintext)
}

func (c *SecureChat) verifyMAC(message, mac string) bool {
	expected := computeHMAC(message, c.key)
	return expected == mac
}

func (c *SecureChat) GetKey() string {
	return hex.EncodeToString(c.key)
}

func (c *SecureChat) Close() error {
	return c.conn.Close()
}

func computeHMAC(message string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *SecureChat) GetProtocolInfo() string {
	return `UDP Chat Protocol:

1. Connectionless (no handshake)
2. Messages may be lost/duplicated
3. No ordering guarantee

Security Implementation:
- AES-256-CBC for confidentiality
- HMAC-SHA256 for integrity
- Unique IV per message
- Key shared via secure channel`
}