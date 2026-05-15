package diffiehellman

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type DiffieHellmanAlgo struct {
	P *big.Int
	G *big.Int
}

func InitDiffieHellman(p, g int) *DiffieHellmanAlgo {
	return &DiffieHellmanAlgo{
		P: big.NewInt(int64(p)),
		G: big.NewInt(int64(g)),
	}
}

func (d *DiffieHellmanAlgo) GenerateKeys() string {
	privateKey, _ := rand.Int(rand.Reader, d.P)
	privateKey.Add(privateKey, big.NewInt(2))

	publicKey := new(big.Int).Exp(d.G, privateKey, d.P)

	return fmt.Sprintf("Private: %s\nPublic: %s\n", privateKey.String(), publicKey.String())
}

func (d *DiffieHellmanAlgo) ComputeSharedSecret(otherPublicKeyFile string) string {
	otherPublicKey := new(big.Int)
	otherPublicKey.SetString(otherPublicKeyFile, 10)

	privateKey, _ := rand.Int(rand.Reader, d.P)
	privateKey.Add(privateKey, big.NewInt(2))

	publicKey := new(big.Int).Exp(d.G, privateKey, d.P)

	sharedSecret := new(big.Int).Exp(otherPublicKey, privateKey, d.P)

	return fmt.Sprintf("Private: %s\nPublic: %s\nShared Secret: %s\n", privateKey.String(), publicKey.String(), sharedSecret.String())
}

func (d *DiffieHellmanAlgo) GeneratePrimeAndGenerator(primeSize int) *big.Int {
	p, _ := rand.Prime(rand.Reader, primeSize)
	d.P = p
	d.G = big.NewInt(2)
	return p
}