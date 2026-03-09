package playfair

import (
	"fmt"
	"strings"
)

type PlayfairAlgo struct {
	matrix [5][5]byte
}

func InitPlayfair(key string) *PlayfairAlgo {
	key = strings.ToUpper(strings.ReplaceAll(key, " ", ""))
	key = strings.ReplaceAll(key, "J", "I")

	var matrix [5][5]byte
	used := make(map[byte]bool)

	idx := 0
	for _, c := range key {
		if c >= 'A' && c <= 'Z' && !used[byte(c)] {
			matrix[idx/5][idx%5] = byte(c)
			used[byte(c)] = true
			idx++
		}
	}

	for c := 'A'; c <= 'Z' && idx < 25; c++ {
		if c != 'J' && !used[byte(c)] {
			matrix[idx/5][idx%5] = byte(c)
			used[byte(c)] = true
			idx++
		}
	}

	return &PlayfairAlgo{matrix: matrix}
}

func (p *PlayfairAlgo) findPos(char byte) (int, int) {
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if p.matrix[i][j] == char {
				return i, j
			}
		}
	}
	return -1, -1
}

func (p *PlayfairAlgo) prepareText(text string) string {
	text = strings.ToUpper(strings.ReplaceAll(text, " ", ""))
	text = strings.ReplaceAll(text, "J", "I")

	var result []rune
	for _, c := range text {
		if c >= 'A' && c <= 'Z' {
			result = append(result, c)
		}
	}

	var prepared []rune
	for i := 0; i < len(result); i++ {
		prepared = append(prepared, result[i])
		if i+1 < len(result) && result[i] == result[i+1] {
			prepared = append(prepared, 'X')
		}
	}

	if len(prepared)%2 == 1 {
		prepared = append(prepared, 'X')
	}

	return string(prepared)
}

func (p *PlayfairAlgo) Encrypt(plaintext string) string {
	plaintext = p.prepareText(plaintext)
	var result []rune

	for i := 0; i < len(plaintext); i += 2 {
		r1, c1 := p.findPos(byte(plaintext[i]))
		r2, c2 := p.findPos(byte(plaintext[i+1]))

		if r1 == r2 {
			result = append(result, rune(p.matrix[r1][(c1+1)%5]))
			result = append(result, rune(p.matrix[r2][(c2+1)%5]))
		} else if c1 == c2 {
			result = append(result, rune(p.matrix[(r1+1)%5][c1]))
			result = append(result, rune(p.matrix[(r2+1)%5][c2]))
		} else {
			result = append(result, rune(p.matrix[r1][c2]))
			result = append(result, rune(p.matrix[r2][c1]))
		}
	}

	return string(result)
}

func (p *PlayfairAlgo) Decrypt(ciphertext string) string {
	if len(ciphertext)%2 != 0 {
		return "Invalid ciphertext length"
	}

	var result []rune

	for i := 0; i < len(ciphertext); i += 2 {
		r1, c1 := p.findPos(byte(ciphertext[i]))
		r2, c2 := p.findPos(byte(ciphertext[i+1]))

		if r1 == r2 {
			result = append(result, rune(p.matrix[r1][(c1+4)%5]))
			result = append(result, rune(p.matrix[r2][(c2+4)%5]))
		} else if c1 == c2 {
			result = append(result, rune(p.matrix[(r1+4)%5][c1]))
			result = append(result, rune(p.matrix[(r2+4)%5][c2]))
		} else {
			result = append(result, rune(p.matrix[r1][c2]))
			result = append(result, rune(p.matrix[r2][c1]))
		}
	}

	for i := 1; i < len(result)-1; i += 2 {
		if result[i] == 'X' {
			result = append(result[:i], result[i+1:]...)
		}
	}

	return string(result)
}

func main() {
	p := InitPlayfair("KEYWORD")
	enc := p.Encrypt("HELLO")
	fmt.Println(enc)
	dec := p.Decrypt(enc)
	fmt.Println(dec)
}
