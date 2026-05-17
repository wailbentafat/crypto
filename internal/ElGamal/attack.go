package elgamal

import (
	"fmt"
	"math/big"
	"sync"
)

func (e *ElGamalAlgo) DemonstrateMalleability(plaintext *big.Int) MalleabilityDemo {
	p := e.p
	g := e.g

	k1, _ := new(big.Int).SetString("12345678901234567890", 10)
	r1 := new(big.Int).Exp(g, k1, p)

	c1 := new(big.Int).Mul(r1, plaintext)
	c1.Mod(c1, p)

	k2, _ := new(big.Int).SetString("98765432109876543210", 10)
	r2 := new(big.Int).Exp(g, k2, p)

	c2 := new(big.Int).Mul(r2, plaintext)
	c2.Mod(c2, p)

	_ = big.NewInt(2)

	forgedK, _ := new(big.Int).SetString("55555555555555555555", 10)
	forgedR := new(big.Int).Exp(g, forgedK, p)

	forgedC1 := new(big.Int).Mul(forgedR, c1)
	forgedC1.Mod(forgedC1, p)

	forgedC2 := new(big.Int).Mul(forgedR, c2)
	forgedC2.Mod(forgedC2, p)

	forgedM1 := new(big.Int).Mul(c1, c2)
	forgedM1.Mod(forgedM1, p)

	_ = Ciphertext{
		C1: new(big.Int).Mul(c1, c2),
		C2: new(big.Int).Mul(r1, r2),
	}

	verification := verifyMalleability(c1, c2, p)

	return MalleabilityDemo{
		OriginalCipher1:   c1.Text(10),
		OriginalCipher2:   c2.Text(10),
		ForgedCipher1:    forgedC1.Text(10),
		ForgedCipher2:    forgedC2.Text(10),
		Verification:     verification,
		AttackPossible:   true,
		AttackDescription: "Given E(m) = (g^k, m*y^k), attacker can compute E(2m) = (g^k, 2*m*y^k) without knowing m or private key",
	}
}

func verifyMalleability(c1, c2 *big.Int, p *big.Int) string {
	return fmt.Sprintf("E(m1) * E(m2) = (g^k1 * g^k2, m1*y^k1 * m2*y^k2) = E(m1*m2)")
}

func (e *ElGamalAlgo) EncryptDeterministic(plaintext *big.Int) Ciphertext {
	k := big.NewInt(7)

	r := new(big.Int).Exp(e.g, k, e.p)

	c1 := new(big.Int).Exp(e.PublicKey, k, e.p)

	c2 := new(big.Int).Mul(r, plaintext)
	c2.Mod(c2, e.p)

	return Ciphertext{
		C1: c1,
		C2: c2,
	}
}

func (e *ElGamalAlgo) DemonstrateNonDeterminism(plaintext *big.Int) []Ciphertext {
	var results []Ciphertext

	for i := 0; i < 5; i++ {
		cipher := e.EncryptDeterministic(plaintext)
		results = append(results, cipher)
	}

	return results
}

func CompareCiphertexts(c1, c2 Ciphertext) bool {
	return c1.C1.Cmp(c2.C1) == 0 && c1.C2.Cmp(c2.C2) == 0
}

func (e *ElGamalAlgo) CiphertextToString(c Ciphertext) string {
	return c.C1.Text(16) + ":" + c.C2.Text(16)
}

func StringToCiphertext(s string) (Ciphertext, error) {
	var c Ciphertext
	fmt.Sscanf(s, "%s:%s", c.C1, c.C2)
	return c, nil
}

func (e *ElGamalAlgo) CompareKeySizes() KeySizeComparison {
	rsaBits := 2048
	elGamalBits := 2048

	return KeySizeComparison{
		RSA_Public_N:     rsaBits,
		RSA_Private_D:    rsaBits,
		RSA_Ciphertext:   rsaBits / 8,
		ElGamal_Prime:    elGamalBits,
		ElGamal_G:        elGamalBits,
		ElGamal_Y:        elGamalBits,
		ElGamal_C1:       elGamalBits / 8,
		ElGamal_C2:       elGamalBits / 8,
		ElGamal_Total:    elGamalBits / 4,
		Explanation:      "ElGamal ciphertext is 2x larger than RSA for equivalent security due to two components (C1, C2)",
	}
}

func (e *ElGamalAlgo) ChosenCiphertextAttack(publicKey *big.Int, p, g *big.Int) string {
	return `Chosen Ciphertext Attack on ElGamal:

1. Attacker intercepts ciphertext C = (C1, C2) intended for victim
2. Attacker chooses random r, computes C' = (C1*r, C2*r) mod p
3. Sends C' to victim who decrypts and returns M'
4. Attacker computes: M = M' / r mod p

This is the "Fork" attack - requires victim to sign/decrypt attacker's chosen message.

Countermeasures:
- Use padding (PGP uses opaque formatting)
- Don't decrypt arbitrary messages
- Use authenticated encryption`
}

func (e *ElGamalAlgo) BatchDecryption(ciphertexts []Ciphertext) []string {
	results := make([]string, len(ciphertexts))

	var wg sync.WaitGroup
	for i, c := range ciphertexts {
		wg.Add(1)
		go func(idx int, cipher Ciphertext) {
			defer wg.Done()
			m := e.Decrypt(fmt.Sprintf("C1: %s\nC2: %s", c.C1.String(), c.C2.String()), "")
			results[idx] = m
		}(i, c)
	}
	wg.Wait()

	return results
}

type MalleabilityDemo struct {
	OriginalCipher1   string
	OriginalCipher2   string
	ForgedCipher1     string
	ForgedCipher2     string
	Verification      string
	AttackPossible    bool
	AttackDescription string
}

type KeySizeComparison struct {
	RSA_Public_N      int
	RSA_Private_D     int
	RSA_Ciphertext    int
	ElGamal_Prime     int
	ElGamal_G         int
	ElGamal_Y         int
	ElGamal_C1        int
	ElGamal_C2        int
	ElGamal_Total     int
	Explanation       string
}

func (e *ElGamalAlgo) HomomorphicProperty() string {
	return `ElGamal Multiplicative Homomorphism:

E(m1) * E(m2) = (g^k1, m1*y^k1) * (g^k2, m2*y^k2)
             = (g^(k1+k2), (m1*m2)*y^(k1+k2))
             = E(m1 * m2)

This allows:
- Multiply encrypted values without decrypting
- Create encrypted votes without knowing content
- Useful for e-voting, threshold decryption

But also enables malleability attacks!`
}

type Ciphertext struct {
	C1, C2 *big.Int
}