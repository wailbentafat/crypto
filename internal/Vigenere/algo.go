package vigenere

import (
	"crypto/internal/core"
	"strings"
)

type VigenereAlgo struct {
	key string
}

func InitVigenere(key string) *VigenereAlgo {
	key = strings.ToUpper(strings.ReplaceAll(key, " ", ""))
	return &VigenereAlgo{
		key: key,
	}
}

func (v *VigenereAlgo) Encrypt(plaintext string) string {
	plaintext = strings.ToUpper(plaintext)
	var result []rune
	keyLen := len(v.key)

	for i, r := range plaintext {
		if r >= 'A' && r <= 'Z' {
			num := core.AlphabetMap[r]
			keyNum := core.AlphabetMap[rune(v.key[i%keyLen])]
			newNum := (num + keyNum) % 26
			result = append(result, core.ReverseAlphabetMap[newNum])
		} else {
			result = append(result, r)
		}
	}

	return string(result)
}

func (v *VigenereAlgo) Decrypt(ciphertext string) string {
	ciphertext = strings.ToUpper(ciphertext)
	var result []rune
	keyLen := len(v.key)

	for i, r := range ciphertext {
		if r >= 'A' && r <= 'Z' {
			num := core.AlphabetMap[r]
			keyNum := core.AlphabetMap[rune(v.key[i%keyLen])]
			newNum := (num - keyNum + 26) % 26
			result = append(result, core.ReverseAlphabetMap[newNum])
		} else {
			result = append(result, r)
		}
	}

	return string(result)
}
