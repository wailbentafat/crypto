package caesar

import (
	"crypto/internal/core"
)

type CaesarAlgo struct {
	decalage int
}

func InitCaesar(decalage int) *CaesarAlgo {
	return &CaesarAlgo{
		decalage: decalage,
	}
}

func (c *CaesarAlgo) Encrypt(word string) string {
	runes := []rune(word)
	var results []rune

	for _, r := range runes {
		var replacement rune
		if r >= 'A' && r <= 'Z' {
			num := core.AlphabetMap[r]
			newNum := (num + c.decalage) % 26
			replacement = core.ReverseAlphabetMap[newNum]

		} else if r >= 'a' && r <= 'z' {
			num := core.AlphabetMap[r-'a'+'A']
			newNum := (num + c.decalage) % 26
			replacement = core.ReverseAlphabetMap[newNum] - 'A' + 'a'

		} else {
			replacement = r
		}

		results = append(results, replacement)
	}

	return string(results)
}

func (c *CaesarAlgo) Decrypt(word string) string {
	runes := []rune(word)
	var results []rune

	for _, r := range runes {
		var replacement rune

		if r >= 'A' && r <= 'Z' {
			num := core.AlphabetMap[r]
			newNum := (num - c.decalage + 26) % 26
			replacement = core.ReverseAlphabetMap[newNum]

		} else if r >= 'a' && r <= 'z' {
			num := core.AlphabetMap[r-'a'+'A']
			newNum := (num - c.decalage + 26) % 26
			replacement = core.ReverseAlphabetMap[newNum] - 'A' + 'a'

		} else {
			replacement = r
		}

		results = append(results, replacement)
	}

	return string(results)
}
