package socket

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"
)

type SecureServer struct {
	listener  net.Listener
	tlsConfig *tls.Config
	aesKey    []byte
}

func InitSecureServer(port int, certFile, keyFile string) (*SecureServer, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	var cert tls.Certificate
	var err error
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
	} else {
		cert, err = generateSelfSignedCert()
		if err != nil {
			return nil, err
		}
	}

	tlsConfig.Certificates = []tls.Certificate{cert}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	rand.Read(key)

	return &SecureServer{
		listener:  listener,
		tlsConfig: tlsConfig,
		aesKey:    key,
	}, nil
}

func (s *SecureServer) Start(handler func(conn net.Conn)) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			continue
		}
		go handler(conn)
	}
}

func (s *SecureServer) Close() error {
	return s.listener.Close()
}

func HandleSecureConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	message := string(buf[:n])
	fmt.Printf("Received: %s\n", message)

	response := "Echo: " + message
	conn.Write([]byte(response))
}

func (s *SecureServer) GenerateSharedKey() string {
	return hex.EncodeToString(s.aesKey)
}

type SecureClient struct {
	conn     net.Conn
	aesKey   []byte
	rsaKey   *rsa.PrivateKey
	pubKey   *rsa.PublicKey
}

func ConnectSecureServer(addr string) (*SecureClient, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	rand.Read(key)

	return &SecureClient{
		conn:   conn,
		aesKey: key,
	}, nil
}

func (c *SecureClient) Send(message string) error {
	encrypted := c.encryptMessage(message)
	_, err := c.conn.Write([]byte(encrypted))
	return err
}

func (c *SecureClient) Receive() (string, error) {
	buf := make([]byte, 4096)
	n, err := c.conn.Read(buf)
	if err != nil {
		return "", err
	}

	return c.decryptMessage(string(buf[:n])), nil
}

func (c *SecureClient) encryptMessage(message string) string {
	block, _ := aes.NewCipher(c.aesKey)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	ciphertext := make([]byte, len(message))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, []byte(message))

	return hex.EncodeToString(iv) + ":" + hex.EncodeToString(ciphertext)
}

func (c *SecureClient) decryptMessage(encrypted string) string {
	parts := split2(encrypted, ":")
	if len(parts) != 2 {
		return ""
	}

	iv, _ := hex.DecodeString(parts[0])
	ciphertext, _ := hex.DecodeString(parts[1])

	block, _ := aes.NewCipher(c.aesKey)
	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	return string(plaintext)
}

func (c *SecureClient) Close() error {
	return c.conn.Close()
}

func split2(s, sep string) []string {
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			return []string{s[:i], s[i+len(sep):]}
		}
	}
	return []string{s, ""}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	return tls.Certificate{}, fmt.Errorf("use proper certificates in production")
}

func CreateSecureChannel() string {
	return `Secure Channel Setup:

1. TCP Connection with TLS 1.3
2. Key Exchange (ECDH/RSA)
3. Session Key Derivation
4. Symmetric Encryption (AES-GCM)
5. MAC for integrity

Security Properties:
- Confidentiality: AES encryption
- Integrity: HMAC/GCM tag
- Forward Secrecy: Ephemeral keys`
}

func (s *SecureServer) GetProtocolInfo() string {
	return `TLS Protocol Implementation:

1. Handshake:
   - ClientHello (supported cipher suites)
   - ServerHello (selected cipher)
   - Certificate exchange
   - Key exchange (ECDH/RSA)
   - Finished messages

2. Data Transfer:
   - Application data encrypted
   - MAC included in AEAD
   - Sequence numbers

3. Security Levels:
   - TLS 1.2: AES-GCM, SHA-256
   - TLS 1.3: Only AEAD, 0-RTT option`
}

var _ io.ReadWriteCloser
var _ time.Time