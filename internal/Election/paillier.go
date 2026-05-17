package election

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type Paillier struct {
	n        *big.Int
	nSquared *big.Int
	g        *big.Int
	lambda   *big.Int
	mu       *big.Int
	pubKey   PublicKey
	privKey  PrivateKey
}

type PublicKey struct {
	N *big.Int
	G *big.Int
}

type PrivateKey struct {
	Lambda *big.Int
	Mu     *big.Int
}

type Vote struct {
	Candidate int
	Encrypted string
}

type Ballot struct {
	VoterID string
	Vote    Vote
	Signature string
}

type ElectionResult struct {
	TotalVotes     int
	SumEncrypted   *big.Int
	SumDecrypted   int
	Winner         string
	Verifiable     bool
}

func InitPaillier(bits int) (*Paillier, error) {
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}

	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).Mul(p, q)
	nSquared := new(big.Int).Mul(n, n)

	lambda := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	g := new(big.Int).Add(n, big.NewInt(1))

	mu := modInverse(lambda, n)

	pk := PublicKey{N: n, G: g}
	prk := PrivateKey{Lambda: lambda, Mu: mu}

	return &Paillier{
		n:        n,
		nSquared: nSquared,
		g:        g,
		lambda:   lambda,
		mu:       mu,
		pubKey:   pk,
		privKey:  prk,
	}, nil
}

func (p *Paillier) Encrypt(m int) (string, error) {
	if m < 0 || m > int(p.pubKey.N.Int64()) {
		return "", fmt.Errorf("message out of range")
	}

	r, err := rand.Int(rand.Reader, p.pubKey.N)
	if err != nil {
		return "", err
	}

	mBig := big.NewInt(int64(m))
	gM := new(big.Int).Exp(p.pubKey.G, mBig, p.nSquared)

	nPlus1 := new(big.Int).Add(p.pubKey.N, big.NewInt(1))
	rN := new(big.Int).Exp(r, p.pubKey.N, p.nSquared)
	rNPlus1 := new(big.Int).Mul(rN, nPlus1)

	c := new(big.Int).Mod(new(big.Int).Mul(gM, rNPlus1), p.nSquared)

	return c.Text(16), nil
}

func (p *Paillier) Decrypt(cHex string) (int, error) {
	c, ok := new(big.Int).SetString(cHex, 16)
	if !ok {
		return 0, fmt.Errorf("invalid ciphertext")
	}

	nSquared := new(big.Int).Mul(p.pubKey.N, p.pubKey.N)

	cLambda := new(big.Int).Exp(c, p.privKey.Lambda, nSquared)

	lx := lFunction(cLambda, p.pubKey.N)
	lxMu := new(big.Int).Mul(lx, p.privKey.Mu)
	m := new(big.Int).Mod(lxMu, p.pubKey.N)

	return int(m.Int64()), nil
}

func lFunction(x, n *big.Int) *big.Int {
	one := big.NewInt(1)
	sub := new(big.Int).Sub(x, one)
	return new(big.Int).Div(sub, n)
}

func (p *Paillier) HomomorphicAdd(c1Hex, c2Hex string) (string, error) {
	c1, ok := new(big.Int).SetString(c1Hex, 16)
	if !ok {
		return "", fmt.Errorf("invalid ciphertext 1")
	}

	c2, ok := new(big.Int).SetString(c2Hex, 16)
	if !ok {
		return "", fmt.Errorf("invalid ciphertext 2")
	}

	nSquared := new(big.Int).Mul(p.pubKey.N, p.pubKey.N)
	result := new(big.Int).Mod(new(big.Int).Mul(c1, c2), nSquared)

	return result.Text(16), nil
}

func (p *Paillier) GetPublicKey() PublicKey {
	return p.pubKey
}

func (p *Paillier) GetPrivateKey() PrivateKey {
	return p.privKey
}

func (p *Paillier) CreateBallot(voterID string, candidate int) (Ballot, error) {
	encrypted, err := p.Encrypt(candidate)
	if err != nil {
		return Ballot{}, err
	}

	signature := p.signBallot(voterID + encrypted)

	return Ballot{
		VoterID:    voterID,
		Vote:       Vote{Candidate: candidate, Encrypted: encrypted},
		Signature:  signature,
	}, nil
}

func (p *Paillier) signBallot(data string) string {
	h := sha256.Sum256([]byte(data))
	hInt := new(big.Int).SetBytes(h[:])
	hInt.Mod(hInt, p.n)

	sig := new(big.Int).Exp(hInt, p.privKey.Lambda, p.n)
	return sig.Text(16)
}

func (p *Paillier) VerifyBallot(ballot Ballot) bool {
	data := ballot.VoterID + ballot.Vote.Encrypted

	h := sha256.Sum256([]byte(data))
	hInt := new(big.Int).SetBytes(h[:])
	hInt.Mod(hInt, p.n)

	sig, _ := new(big.Int).SetString(ballot.Signature, 16)

	verify := new(big.Int).Exp(sig, big.NewInt(2), p.n)

	return verify.Cmp(hInt) == 0
}

func TallyVotes(ballots []Ballot, election *Paillier) (ElectionResult, error) {
	if len(ballots) == 0 {
		return ElectionResult{}, fmt.Errorf("no ballots to tally")
	}

	sumEncrypted, err := election.Decrypt(ballots[0].Vote.Encrypted)
	if err != nil {
		return ElectionResult{}, err
	}
	sumBig := big.NewInt(int64(sumEncrypted))

	for i := 1; i < len(ballots); i++ {
		sumEncrypted, err = election.Decrypt(ballots[i].Vote.Encrypted)
		if err != nil {
			return ElectionResult{}, err
		}

		homomorphic, err := election.HomomorphicAdd(
			big.NewInt(int64(sumEncrypted)).Text(16),
			big.NewInt(int64(sumEncrypted)).Text(16),
		)
		if err != nil {
			return ElectionResult{}, err
		}

		v, _ := election.Decrypt(homomorphic)
		sumBig.Add(sumBig, big.NewInt(int64(v)))
	}

	totalVotes := len(ballots)
	sumDecrypted := 0

	for _, b := range ballots {
		v, _ := election.Decrypt(b.Vote.Encrypted)
		sumDecrypted += v
	}

	candidates := []string{"Candidate A", "Candidate B", "Candidate C"}
	winner := candidates[sumDecrypted%len(candidates)]

	return ElectionResult{
		TotalVotes:     totalVotes,
		SumEncrypted:   big.NewInt(int64(sumDecrypted)),
		SumDecrypted:   sumDecrypted,
		Winner:         winner,
		Verifiable:     true,
	}, nil
}

func (p *Paillier) GetDescription() string {
	return `Paillier Homomorphic Encryption:

Properties:
1. Additive homomorphism:
   E(m1) * E(m2) = E(m1 + m2)

2. Used for e-voting:
   - Each vote encrypted individually
   - Tallies computed on encrypted votes
   - Only final result decrypted

3. Security:
   - Based on decisional composite residuosity
   - 2048-bit provides ~112-bit security
   - Semantic security (IND-CPA)`
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