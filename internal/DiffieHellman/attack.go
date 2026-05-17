package diffiehellman

import (
	"math/big"
	"time"
)

type MITMAttack struct {
	alicePubKey *big.Int
	bobPubKey   *big.Int
	attackerPriv *big.Int
	p, g         *big.Int
}

func (d *DiffieHellmanAlgo) SimulateMITM(p, g *big.Int) MITMAttackResult {
	attackerPriv, _ := new(big.Int).SetString("12345", 10)

	attackerPubA := new(big.Int).Exp(g, attackerPriv, p)

	A := new(big.Int).Exp(g, new(big.Int).SetInt64(123), p)

	attackerPubB := new(big.Int).Exp(g, attackerPriv, p)

	B := new(big.Int).Exp(g, new(big.Int).SetInt64(456), p)

	sharedA := new(big.Int).Exp(A, attackerPriv, p)

	sharedB := new(big.Int).Exp(B, attackerPriv, p)

	return MITMAttackResult{
		Prime:          p.Text(10),
		Generator:      g.Text(10),
		AlicePublic:    A.Text(10),
		BobPublic:      B.Text(10),
		AttackerPubA:   attackerPubA.Text(10),
		AttackerPubB:   attackerPubB.Text(10),
		AliceShared:    sharedA.Text(10),
		BobShared:      sharedB.Text(10),
		AttackersView:  "Attacker sees two different shared secrets",
	}
}

func (d *DiffieHellmanAlgo) DetectMITM(originalPubA, originalPubB, receivedPubA, receivedPubB *big.Int) bool {
	return originalPubA.Cmp(receivedPubA) != 0 || originalPubB.Cmp(receivedPubB) != 0
}

func (d *DiffieHellmanAlgo) SignedKeyExchange(p, g *big.Int, alicePriv, bobPriv *big.Int) SignedExchangeResult {
	alicePub := new(big.Int).Exp(g, alicePriv, p)
	bobPub := new(big.Int).Exp(g, bobPriv, p)

	aliceShared := new(big.Int).Exp(bobPub, alicePriv, p)
	bobShared := new(big.Int).Exp(alicePub, bobPriv, p)

	aliceSign := signMessage(alicePub, alicePriv)
	bobSign := signMessage(bobPub, bobPriv)

	aliceVerified := verifySignature(alicePub, aliceSign, alicePub)
	bobVerified := verifySignature(bobPub, bobSign, bobPub)

	return SignedExchangeResult{
		AlicePublicKey:  alicePub.Text(10),
		BobPublicKey:   bobPub.Text(10),
		AliceShared:    aliceShared.Text(10),
		BobShared:     bobShared.Text(10),
		AliceSigned:   aliceVerified,
		BobSigned:     bobVerified,
		Secure:        aliceVerified && bobVerified,
	}
}

type MITMAttackResult struct {
	Prime         string
	Generator     string
	AlicePublic   string
	BobPublic     string
	AttackerPubA  string
	AttackerPubB  string
	AliceShared   string
	BobShared     string
	AttackersView string
}

type SignedExchangeResult struct {
	AlicePublicKey string
	BobPublicKey   string
	AliceShared    string
	BobShared      string
	AliceSigned    bool
	BobSigned      bool
	Secure         bool
}

func signMessage(message *big.Int, privateKey *big.Int) *big.Int {
	hash := simpleHash(message.Text(10))
	return new(big.Int).Exp(hash, privateKey, privateKey)
}

func verifySignature(message, signature, publicKey *big.Int) bool {
	hash := simpleHash(message.Text(10))
	expected := new(big.Int).Exp(signature, publicKey, publicKey)
	return expected.Cmp(hash) == 0
}

func simpleHash(s string) *big.Int {
	hash := big.NewInt(0)
	for i := range s {
		hash.Mul(hash, big.NewInt(31))
		hash.Add(hash, big.NewInt(int64(s[i])))
	}
	return hash
}

func (d *DiffieHellmanAlgo) ComputeDiscreteLog(target, base, mod *big.Int) *big.Int {
	_ = time.Now()

	limit := new(big.Int).Sqrt(mod)
	limit.Add(limit, big.NewInt(1))

	table := make(map[string]*big.Int)

	step := big.NewInt(1)
	for step.Cmp(limit) < 0 {
		value := new(big.Int).Exp(base, step, mod)
		table[value.Text(10)] = new(big.Int).Set(step)
		step.Add(step, big.NewInt(1))
	}

	inverseBase := modInverse(base, mod)
	if inverseBase == nil {
		return nil
	}

	current := new(big.Int).Set(target)
	for i := int64(0); i < 1000; i++ {
		if val, ok := table[current.Text(10)]; ok {
			result := new(big.Int).Sub(val, big.NewInt(i))
			if result.Sign() > 0 {
				return result
			}
		}
		current.Mul(current, inverseBase)
		current.Mod(current, mod)
	}

	return nil
}

func modInverse(a, m *big.Int) *big.Int {
	a = new(big.Int).Mod(a, m)
	if a.Sign() < 0 {
		a.Add(a, m)
	}

	g, x, _ := extendedGCD(a, m)
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil
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

type WeakDHParams struct {
	P *big.Int
	G *big.Int
}

var WeakDHParamsList = []WeakDHParams{
	{big.NewInt(239), big.NewInt(2)},
	{big.NewInt(257), big.NewInt(2)},
	{big.NewInt(307), big.NewInt(2)},
	{big.NewInt(347), big.NewInt(2)},
	{big.NewInt(359), big.NewInt(2)},
}

func (d *DiffieHellmanAlgo) CheckWeakParams(p *big.Int) bool {
	for _, weak := range WeakDHParamsList {
		if p.Cmp(weak.P) == 0 {
			return true
		}
	}
	return false
}

func (d *DiffieHellmanAlgo) GenerateStrongParams(bits int) (p, g *big.Int) {
	p = generatePrime(bits)
	g = big.NewInt(2)
	return
}

func generatePrime(bits int) *big.Int {
	for {
		p, _ := new(big.Int).SetString(generateRandomHex(bits/8), 16)
		if p.Bit(bits-1) == 1 {
			p.SetBit(p, bits-1, 1)
		}
		if p.ProbablyPrime(20) {
			return p
		}
	}
}

func generateRandomHex(n int) string {
	hexChars := "0123456789ABCDEF"
	result := make([]byte, n)
	for i := range result {
		result[i] = hexChars[int(time.Now().UnixNano()%16)]
		time.Sleep(time.Nanosecond)
	}
	return string(result)
}

func (d *DiffieHellmanAlgo) GetAttackDescription() string {
	return `MITM Attack on Diffie-Hellman:

1. Attacker intercepts Alice's public key A = g^a mod p
2. Attacker replaces it with A' = g^x mod p and sends to Bob
3. Attacker intercepts Bob's public key B = g^b mod p
4. Attacker replaces it with B' = g^x mod p and sends to Alice

Result:
- Alice computes K1 = (B')^a = g^(xa) mod p
- Bob computes K2 = (A')^b = g^(xb) mod p
- Attacker computes both K1 and K2 using private key x

Defense: Use authenticated key exchange (ECDHE) or certificates`}