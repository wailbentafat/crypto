package affine

import (
	"crypto/internal/core"
	"fmt"
)

type AffineAlgo struct {
	a int
	b int
}

func InitAffine(a, b int) *AffineAlgo {
	if gcd(a, 26) != 1 {
		fmt.Println("Warning: a must be coprime with 26, using default a=1")
		a = 1
	}
	return &AffineAlgo{
		a: a,
		b: b,
	}
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func modInverse(a, m int) int {
	a = ((a % m) + m) % m
	for i := 1; i < m; i++ {
		if (a*i)%m == 1 {
			return i
		}
	}
	return 1
}

func (a *AffineAlgo) Encrypt(word string) string {
	runes := []rune(word)
	var results []rune

	for _, r := range runes {
		var replacement rune
		if r >= 'A' && r <= 'Z' {
			num := core.AlphabetMap[r]
			newNum := (a.a*num + a.b) % 26
			replacement = core.ReverseAlphabetMap[newNum]
		} else if r >= 'a' && r <= 'z' {
			num := core.AlphabetMap[r-'a'+'A']
			newNum := (a.a*num + a.b) % 26
			replacement = core.ReverseAlphabetMap[newNum] - 'A' + 'a'
		} else {
			replacement = r
		}
		results = append(results, replacement)
	}

	return string(results)
}

func (a *AffineAlgo) Decrypt(word string) string {
	runes := []rune(word)
	var results []rune

	aInv := modInverse(a.a, 26)

	for _, r := range runes {
		var replacement rune
		if r >= 'A' && r <= 'Z' {
			num := core.AlphabetMap[r]
			newNum := (aInv * (num - a.b + 26)) % 26
			replacement = core.ReverseAlphabetMap[newNum]
		} else if r >= 'a' && r <= 'z' {
			num := core.AlphabetMap[r-'a'+'A']
			newNum := (aInv * (num - a.b + 26)) % 26
			replacement = core.ReverseAlphabetMap[newNum] - 'A' + 'a'
		} else {
			replacement = r
		}
		results = append(results, replacement)
	}

	return string(results)
}

func (a *AffineAlgo) EncryptNumber(x int) int {
	return (a.a*x + a.b) % 26
}

func (a *AffineAlgo) DecryptNumber(y int) int {
	aInv := modInverse(a.a, 26)
	return (aInv * (y - a.b + 26)) % 26
}
