package diffiehellman

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type DiffieHellmanAlgo struct {
	p *big.Int
	g *big.Int
}

func InitDiffieHellman(p, g int) *DiffieHellmanAlgo {
	return &DiffieHellmanAlgo{
		p: big.NewInt(int64(p)),
		g: big.NewInt(int64(g)),
	}
}

func (d *DiffieHellmanAlgo) GenerateKeys() string {
	privateKey, _ := rand.Int(rand.Reader, d.p)
	privateKey.Add(privateKey, big.NewInt(2))

	publicKey := new(big.Int).Exp(d.g, privateKey, d.p)

	return fmt.Sprintf("Private: %s\nPublic: %s\n", privateKey.String(), publicKey.String())
}

func (d *DiffieHellmanAlgo) ComputeSharedSecret(otherPublicKeyFile string) string {
	otherPublicKey := new(big.Int)
	otherPublicKey.SetString(otherPublicKeyFile, 10)

	privateKey, _ := rand.Int(rand.Reader, d.p)
	privateKey.Add(privateKey, big.NewInt(2))

	publicKey := new(big.Int).Exp(d.g, privateKey, d.p)

	sharedSecret := new(big.Int).Exp(otherPublicKey, privateKey, d.p)

	return fmt.Sprintf("Private: %s\nPublic: %s\nShared Secret: %s\n", privateKey.String(), publicKey.String(), sharedSecret.String())
}

func (d *DiffieHellmanAlgo) GeneratePrimeAndGenerator(primeSize int) (p, g *big.Int) {
	p, _ = rand.Prime(rand.Reader, primeSize)
	g = big.NewInt(2)
	return
}
