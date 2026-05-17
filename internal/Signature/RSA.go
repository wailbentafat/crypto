package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

type RSASignature struct {
	privateKey *rsa.PrivateKey
	publicKey *rsa.PublicKey
}

func InitRSASignature(bits int) (*RSASignature, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return &RSASignature{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

func (r *RSASignature) SignPKCS1v15(message string) (string, error) {
	h := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

func (r *RSASignature) VerifyPKCS1v15(message, signatureHex string) bool {
	h := sha256.Sum256([]byte(message))
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	return rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA256, h[:], signature) == nil
}

func (r *RSASignature) SignPSS(message string) (string, error) {
	h := sha256.Sum256([]byte(message))

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}

	signature, err := rsa.SignPSS(rand.Reader, r.privateKey, crypto.SHA256, h[:], opts)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

func (r *RSASignature) VerifyPSS(message, signatureHex string) bool {
	h := sha256.Sum256([]byte(message))
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}

	return rsa.VerifyPSS(r.publicKey, crypto.SHA256, h[:], signature, opts) == nil
}

func (r *RSASignature) SignWithSalt(message string, saltLen int) (string, error) {
	h := sha256.Sum256([]byte(message))

	opts := &rsa.PSSOptions{
		SaltLength: saltLen,
	}

	signature, err := rsa.SignPSS(rand.Reader, r.privateKey, crypto.SHA256, h[:], opts)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

func (r *RSASignature) GetPublicKey() string {
	return fmt.Sprintf("N: %s\nE: %d", r.publicKey.N.Text(16), r.publicKey.E)
}

func (r *RSASignature) GetPrivateKey() string {
	return r.privateKey.D.Text(16)
}

func (r *RSASignature) GetKeySizes() KeySizeInfo {
	return KeySizeInfo{
		N_Bits:   r.privateKey.N.BitLen(),
		E_Bits:   16,
		D_Bits:   r.privateKey.D.BitLen(),
		P_Bits:   r.privateKey.Primes[0].BitLen(),
		Q_Bits:   r.privateKey.Primes[1].BitLen(),
	}
}

type KeySizeInfo struct {
	N_Bits int
	E_Bits int
	D_Bits int
	P_Bits int
	Q_Bits int
}

func (r *RSASignature) GetDescription() string {
	return `RSA Signatures:

PKCS#1 v1.5 (RSASSA-PKCS1-v1_5):
- Hash + DigestInfo + RSA encryption
- Vulnerable to Bleichenbacher's attack (Manger's)
- Being deprecated in TLS 1.3

PSS (RSASSA-PSS):
- Probabilistic signature scheme
- Uses random salt
- Provably secure (ROS assumption)
- Recommended for new applications`
}

func (r *RSASignature) AttackDescription() string {
	return `RSA Signature Attacks:

1. PKCS#1 v1.5 Attack (Bleichenbacher):
   - Attacker sends modified ciphertext
   - Server reveals whether padding is valid
   - Can recover plaintext byte by byte

2. Fault Attack:
   - Induce random bit flip during decryption
   - Use faulty signature to compute private key

3. Small e Attack:
   - If e=3 and message hash < n^(1/3)
   - Can recover message via cube root

Countermeasure: Use PSS padding`
}

func CompareRSAAlgorithms(message string) RSAComparison {
	sig, _ := InitRSASignature(2048)

	pkcs1Sig, _ := sig.SignPKCS1v15(message)
	pssSig, _ := sig.SignPSS(message)

	return RSAComparison{
		Message:          message,
		PKCS1v15_Signature: pkcs1Sig,
		PSS_Signature:     pssSig,
		PKCS1v15_Length:   len(pkcs1Sig) / 2,
		PSS_Length:        len(pssSig) / 2,
		Security_Level:    "PSS offers better security guarantees",
	}
}

type RSAComparison struct {
	Message          string
	PKCS1v15_Signature string
	PSS_Signature     string
	PKCS1v15_Length   int
	PSS_Length        int
	Security_Level    string
}

func (r *RSASignature) DeterministicSign(message string) (string, error) {
	h := sha256.Sum256([]byte(message))

	opts := &rsa.PSSOptions{
		SaltLength: 0,
	}

	signature, err := rsa.SignPSS(rand.Reader, r.privateKey, crypto.SHA256, h[:], opts)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

var _ = big.NewInt