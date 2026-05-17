package signature

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type ECDSA struct {
	curve  elliptic.Curve
	privateKey *big.Int
	publicKey  *big.Int
}

func InitECDSA(curveName string) (*ECDSA, error) {
	var curve elliptic.Curve

	switch curveName {
	case "P-224":
		curve = elliptic.P224()
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
	}

	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	_ = y

	return &ECDSA{
		curve:      curve,
		privateKey: new(big.Int).SetBytes(privateKey),
		publicKey:  x,
	}, nil
}

func (e *ECDSA) Sign(message string) (string, error) {
	h := sha256.Sum256([]byte(message))
	hInt := new(big.Int).SetBytes(h[:])

	hInt.Mod(hInt, e.curve.Params().N)

	signature := e.signWithK(message, hInt)

	return signature, nil
}

func (e *ECDSA) signWithK(message string, hInt *big.Int) string {
	n := e.curve.Params().N

	for {
		k, _ := rand.Int(rand.Reader, n)

		r, _ := e.curve.ScalarBaseMult(k.Bytes())
		r.Mod(r, n)
		if r.Sign() == 0 {
			continue
		}

		kInv := modInverse(k, n)
		if kInv.Sign() == 0 {
			continue
		}

		s := new(big.Int).Mul(kInv, hInt)
		s.Add(s, new(big.Int).Mul(e.privateKey, r))
		s.Mod(s, n)
		if s.Sign() == 0 {
			continue
		}

		return fmt.Sprintf("%s:%s", r.Text(16), s.Text(16))
	}
}

func (e *ECDSA) Verify(message, signature string) bool {
	h := sha256.Sum256([]byte(message))
	hInt := new(big.Int).SetBytes(h[:])

	hInt.Mod(hInt, e.curve.Params().N)

	var r, s big.Int
	fmt.Sscanf(signature, "%s:%s", &r, &s)

	n := e.curve.Params().N
	if r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return false
	}
	if s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return false
	}

	w := modInverse(&s, n)
	if w.Sign() == 0 {
		return false
	}

	u1 := new(big.Int).Mul(w, hInt)
	u1.Mod(u1, n)

	u2 := new(big.Int).Mul(w, &r)
	u2.Mod(u2, n)

	x, y := e.curve.ScalarMult(e.curve.Params().Gx, e.curve.Params().Gy, u1.Bytes())
	if x == nil {
		return false
	}

	x2, y2 := e.curve.ScalarMult(e.publicKey, nil, u2.Bytes())
	if x2 == nil {
		return false
	}

	x, y = e.curve.Add(x, y, x2, y2)
	if x == nil {
		return false
	}

	x.Mod(x, n)

	return x.Cmp(&r) == 0
}

func (e *ECDSA) GetPublicKey() string {
	return fmt.Sprintf("X: %s\nCurve: %s", e.publicKey.Text(16), e.curve.Params().Name)
}

func (e *ECDSA) GetPrivateKey() string {
	return e.privateKey.Text(16)
}

func (e *ECDSA) GetDescription() string {
	return `ECDSA (Elliptic Curve DSA):

- Based on elliptic curve discrete log
- Uses smaller keys than RSA/DSA
- Same security with 256-bit key as 3072-bit RSA
- Signature size: 2 * curve size (64 bytes for P-256)

Standard Curves:
- P-256 (NIST): Most widely used
- P-384: Higher security
- P-521: Highest security (US government)
- Curve25519: Alternative design`
}

func (e *ECDSA) CompareWithRSA() ECDSAComparison {
	curveSize := e.curve.Params().BitSize

	return ECDSAComparison{
		ECDSA_Curve:   e.curve.Params().Name,
		ECDSA_KeySize: curveSize,
		ECDSA_SigSize: curveSize / 8 * 2,
		RSA_KeySize:   2048,
		RSA_SigSize:   256,
		Explanation:  fmt.Sprintf("ECDSA with %d-bit curve provides similar security to RSA-2048 but with much smaller keys", curveSize),
	}
}

func GetSecurityLevels() []SecurityLevel {
	return []SecurityLevel{
		{Curve: "P-224", KeySize: 224, SecurityBits: 112, RSA_Equivalent: 2048},
		{Curve: "P-256", KeySize: 256, SecurityBits: 128, RSA_Equivalent: 3072},
		{Curve: "P-384", KeySize: 384, SecurityBits: 192, RSA_Equivalent: 7680},
		{Curve: "P-521", KeySize: 521, SecurityBits: 256, RSA_Equivalent: 15360},
	}
}

type ECDSAComparison struct {
	ECDSA_Curve   string
	ECDSA_KeySize int
	ECDSA_SigSize int
	RSA_KeySize   int
	RSA_SigSize   int
	Explanation  string
}

type SecurityLevel struct {
	Curve         string
	KeySize       int
	SecurityBits  int
	RSA_Equivalent int
}

func ECDSASecurityInfo() string {
	return `ECDSA Security Levels (NIST SP 800-57):

Security Level | ECDSA Curve | RSA Equivalent | Notes
---------------|-------------|---------------|-------
80 bits        | P-224       | 2048          | Deprecated
112 bits       | P-256       | 2048          | Minimum
128 bits       | P-256       | 3072          | Recommended
192 bits       | P-384       | 7680          | High security
256 bits       | P-521       | 15360         | Top secret`
}