package signature

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

type DSA struct {
	p, q, g *big.Int
	x       *big.Int
	y       *big.Int
}

func InitDSA(bits int) (*DSA, error) {
	qBits := bits / 4

	q, err := rand.Prime(rand.Reader, qBits)
	if err != nil {
		return nil, err
	}

	p := new(big.Int)
	for {
		h, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits-q.BitLen())))
		p.Mul(h, q)
		p.Add(p, big.NewInt(1))
		if p.ProbablyPrime(20) {
			break
		}
	}

	g := big.NewInt(2)
	for {
		h, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
		g.Exp(h, new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), q), p)
		if g.Cmp(big.NewInt(1)) > 0 {
			break
		}
	}

	x, _ := rand.Int(rand.Reader, q)
	y := new(big.Int).Exp(g, x, p)

	return &DSA{p: p, q: q, g: g, x: x, y: y}, nil
}

func (d *DSA) Sign(message string) (string, error) {
	h := sha256.Sum256([]byte(message))
	z := new(big.Int).SetBytes(h[:])

	z.Mod(z, d.q)

	s1 := big.NewInt(0)
	k := big.NewInt(0)

	for s1.Sign() == 0 || s1.Cmp(big.NewInt(1)) == -1 {
		k, _ = rand.Int(rand.Reader, d.q)

		s1 = new(big.Int).Exp(d.g, k, d.p)
		s1.Mod(s1, d.q)
	}

	kInv := modInverse(k, d.q)

	s2 := new(big.Int).Mul(kInv, z)
	s2.Add(s2, new(big.Int).Mul(d.x, s1))
	s2.Mod(s2, d.q)

	return fmt.Sprintf("%s:%s", s1.Text(16), s2.Text(16)), nil
}

func (d *DSA) Verify(message, signature string) bool {
	h := sha256.Sum256([]byte(message))
	z := new(big.Int).SetBytes(h[:])

	z.Mod(z, d.q)

	var s1, s2 big.Int
	fmt.Sscanf(signature, "%s:%s", &s1, &s2)

	s1.Mod(&s1, d.q)
	s2.Mod(&s2, d.q)

	if s1.Sign() <= 0 || s2.Sign() <= 0 {
		return false
	}

	w := modInverse(&s2, d.q)

	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, d.q)

	u2 := new(big.Int).Mul(&s1, w)
	u2.Mod(u2, d.q)

	v := new(big.Int).Exp(d.g, u1, d.p)
	tmp := new(big.Int).Exp(d.y, u2, d.p)
	v.Mul(v, tmp)
	v.Mod(v, d.p)
	v.Mod(v, d.q)

	return v.Cmp(&s1) == 0
}

func (d *DSA) GetPublicKey() string {
	return fmt.Sprintf("p: %s\nq: %s\ng: %s\ny: %s", d.p.Text(16), d.q.Text(16), d.g.Text(16), d.y.Text(16))
}

func (d *DSA) GetPrivateKey() string {
	return d.x.Text(16)
}

func (d *DSA) GetDescription() string {
	return `DSA (Digital Signature Algorithm):

- US Federal Standard (FIPS 186-4)
- Based on discrete logarithm problem
- Parameters: p (1024-3072 bit), q (160-256 bit)
- Signature: (r, s) where r depends on g^k mod p

Advantages:
- Faster than RSA for same security
- Smaller signatures than RSA

Disadvantages:
- More complex than RSA
- Non-deterministic
- Not suitable for encryption`
}

func (d *DSA) CompareWithRSA() DSACparison {
	return DSACparison{
		DSA_KeySize:  d.p.BitLen(),
		DSA_SigSize:  (d.q.BitLen() / 8) * 2,
		RSA_KeySize:  2048,
		RSA_SigSize:  256,
		Explanation: "DSA produces smaller signatures than RSA for equivalent security",
	}
}

type DSACparison struct {
	DSA_KeySize  int
	DSA_SigSize  int
	RSA_KeySize  int
	RSA_SigSize  int
	Explanation string
}

func CompareDSASignatures() string {
	return `DSA vs RSA Signatures:

DSA:
- Signature size: 320-512 bits (depends on q size)
- Signing: ~same speed as RSA
- Verification: ~slower than RSA
- Key generation: slower

RSA:
- Signature size: equal to key size (2048 bits)
- Signing: slower
- Verification: faster (with public key)
- Key generation: faster (for small e)

NIST SP 800-57 recommendations:
- 2048-bit RSA ≈ 224-bit DSA security
- 3072-bit RSA ≈ 256-bit DSA security`
}

func (d *DSA) SecurityLevel() string {
	return `DSA Security Levels:

Key Size | Security (bits) | Notes
---------|------------------|-------
1024/160 | 80              | Deprecated
2048/224 | 112             | Minimum
3072/256 | 128             | Recommended
4096/256 | 140+            | Future-proof

Note: Only q size determines security (hash truncates to q bits)`
}

var _ = hex.EncodeToString
var _ = sha256.New