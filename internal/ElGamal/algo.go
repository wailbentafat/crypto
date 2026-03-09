package elgamal

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type ElGamalAlgo struct {
	p *big.Int
	g *big.Int
}

func InitElGamal(p, g int) *ElGamalAlgo {
	return &ElGamalAlgo{
		p: big.NewInt(int64(p)),
		g: big.NewInt(int64(g)),
	}
}

func (e *ElGamalAlgo) GenerateKeys() string {
	privateKey, _ := rand.Int(rand.Reader, e.p)
	privateKey.Add(privateKey, big.NewInt(2))

	publicKey := new(big.Int).Exp(e.g, privateKey, e.p)

	return fmt.Sprintf("Private Key: %s\nPublic Key: %s\nPrime (p): %s\nGenerator (g): %s\n",
		privateKey.String(), publicKey.String(), e.p.String(), e.g.String())
}

func (e *ElGamalAlgo) Encrypt(plaintext, pubKeyFile string) string {
	m := new(big.Int)
	m.SetString(plaintext, 10)

	k, _ := rand.Int(rand.Reader, e.p)
	k.Add(k, big.NewInt(2))

	c1 := new(big.Int).Exp(e.g, k, e.p)

	publicKey := new(big.Int)
	publicKey.SetString(pubKeyFile, 10)

	c2 := new(big.Int).Exp(publicKey, k, e.p)
	c2.Mul(c2, m)
	c2.Mod(c2, e.p)

	return fmt.Sprintf("C1: %s\nC2: %s\n", c1.String(), c2.String())
}

func (e *ElGamalAlgo) Decrypt(ciphertext, prvKeyFile string) string {
	var c1, c2 string
	fmt.Sscanf(ciphertext, "C1: %s\nC2: %s", &c1, &c2)

	c1Int := new(big.Int)
	c1Int.SetString(c1, 10)

	c2Int := new(big.Int)
	c2Int.SetString(c2, 10)

	privateKey := new(big.Int)
	privateKey.SetString(prvKeyFile, 10)

	s := new(big.Int).Exp(c1Int, privateKey, e.p)
	s.ModInverse(s, e.p)

	m := new(big.Int).Mul(c2Int, s)
	m.Mod(m, e.p)

	return m.String()
}
