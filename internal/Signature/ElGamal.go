package signature

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type ElGamalSignature struct {
	p        *big.Int
	g        *big.Int
	x        *big.Int
	y        *big.Int
}

func InitElGamalSignature(bits int) (*ElGamalSignature, error) {
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	g := big.NewInt(2)

	x, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, err
	}

	y := new(big.Int).Exp(g, x, p)

	return &ElGamalSignature{
		p: p,
		g: g,
		x: x,
		y: y,
	}, nil
}

func (e *ElGamalSignature) Sign(message string) (string, error) {
	h := simpleHash(message)
	h.Mod(h, e.p)

	k, err := rand.Int(rand.Reader, e.p)
	if err != nil {
		return "", err
	}

	if new(big.Int).GCD(nil, nil, k, e.p).Cmp(big.NewInt(1)) != 0 {
		k, _ = rand.Int(rand.Reader, e.p)
	}

	r := new(big.Int).Exp(e.g, k, e.p)

	kInv := modInverse(k, e.p.Sub(e.p, big.NewInt(1)))

	s := new(big.Int).Mul(kInv, h)
	s.Sub(s, new(big.Int).Mul(e.x, r))
	s.Mod(s, new(big.Int).Sub(e.p, big.NewInt(1)))

	if s.Sign() < 0 {
		s.Add(s, new(big.Int).Sub(e.p, big.NewInt(1)))
	}

	return fmt.Sprintf("%s:%s", r.Text(16), s.Text(16)), nil
}

func (e *ElGamalSignature) Verify(message, signature string) bool {
	h := simpleHash(message)
	h.Mod(h, e.p)

	var r, s big.Int
	fmt.Sscanf(signature, "%s:%s", &r, &s)

	r.Mod(&r, e.p)
	s.Mod(&s, new(big.Int).Sub(e.p, big.NewInt(1)))

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}

	v1 := new(big.Int).Exp(e.g, h, e.p)

	v2 := new(big.Int).Exp(e.y, &r, e.p)
	tmp := new(big.Int).Exp(&r, &s, e.p)
	v2.Mul(v2, tmp)
	v2.Mod(v2, e.p)

	return v1.Cmp(v2) == 0
}

func (e *ElGamalSignature) GetPublicKey() string {
	return fmt.Sprintf("p: %s\ng: %s\ny: %s", e.p.Text(16), e.g.Text(16), e.y.Text(16))
}

func (e *ElGamalSignature) GetPrivateKey() string {
	return e.x.Text(16)
}

func (e *ElGamalSignature) AttackDescription() string {
	return `ElGamal Signature Attack:

1. Reused k Attack (if k is reused):
   - Two signatures with same k: (r, s1) and (r, s2)
   - k = (m1 - m2) * inv(s1 - s2) mod (p-1)
   - Can compute private key x from k

2. Hash Attack:
   - If hash collision, attacker can forge
   - Use different messages with same hash

3. Random k is ESSENTIAL
   - Must use proper PRNG
   - k must be unique per signature`
}

func (e *ElGamalSignature) DemonstrateKeyReuse() KeyReuseDemo {
	sig1, _ := e.Sign("message1")
	sig2, _ := e.Sign("message2")

	return KeyReuseDemo{
		Signature1:   sig1,
		Signature2:   sig2,
		AttackResult: "If k is reused, can compute private key from two signatures",
		Prevention:   "Use unique random k for each signature",
	}
}

func (e *ElGamalSignature) VerifyProperties() string {
	return `ElGamal Signature Properties:

1. Non-deterministic:
   - Same message produces different signatures
   - Due to random k in signature

2. Longer than RSA:
   - Signature size = 2 * key size
   - RSA signature = key size

3. Security depends on:
   - Discrete log hardness
   - Random k generation`
}

type KeyReuseDemo struct {
	Signature1   string
	Signature2   string
	AttackResult string
	Prevention   string
}

func simpleHash(message string) *big.Int {
	h := big.NewInt(0)
	for i := range message {
		h.Mul(h, big.NewInt(31))
		h.Add(h, big.NewInt(int64(message[i])))
	}
	return h
}

func modInverse(a, m *big.Int) *big.Int {
	a = new(big.Int).Mod(a, m)
	if a.Sign() < 0 {
		a.Add(a, m)
	}

	g, x, _ := extendedGCD(a, m)
	if g.Cmp(big.NewInt(1)) != 0 {
		return big.NewInt(0)
	}

	x.Mod(x, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}

	return x
}

func extendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if a.Sign() == 0 {
		return b, big.NewInt(0), big.NewInt(1)
	}
	if b.Sign() == 0 {
		return a, big.NewInt(1), big.NewInt(0)
	}

	g, x1, y1 := extendedGCD(b, new(big.Int).Mod(b, a))

	x := new(big.Int).Sub(y1, new(big.Int).Div(b, a))
	x.Mul(x, x1)

	y := new(big.Int).Sub(x1, x)
	y.Mul(y, a)
	y.Add(y, x1)

	return g, x, y
}

var _ = rand.Reader
var _ = fmt.Sprintf