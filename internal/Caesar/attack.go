package caesar

import (
	"strings"
	"unicode"
)

var FrenchCommonWords = []string{
	"LE", "LA", "LES", "UN", "UNE", "DES", "DE", "DU", "DE",
	"ET", "EST", "E", "S", "T", "A", "QUE", "QUI", "Q",
	"EN", "N", "PAS", "PLUS", "AVOIR", "ETRE", "FAIRE",
	"JE", "TU", "IL", "ELLE", "NOUS", "VOUS", "ILS", "ELLES",
	"MON", "TON", "SON", "MA", "TA", "SA", "NOS", "VOS", "LEURS",
	"CE", "CET", "CETTE", "CES", "C", "D", "L", "J",
	"DANS", "SUR", "PAR", "POUR", "AVEC", "SANS", "SOUS",
	"OU", "MAIS", "DONC", "CAR", "NI", "NE", "NON",
	"TOUT", "TOUTE", "TOUS", "TOUTES", "AUTRE", "AUTRES",
	"MEME", "MEMES", "TEL", "TELLE", "TELS", "TELLES",
	"PEU", "BEAUCOUP", "TRES", "BIEN", "MAL", "VITE",
	"OUI", "NON", "SI", " JAMAIS", "TOUJOURS", "SOUVENT",
	"QUAND", "COMMENT", "POURQUOI", "OU", "ICI", "LA",
	"COMMENCER", "FINIR", "PRENDRE", "DONNER", "VOIR",
	"ETRE", "AVOIR", "FAIRE", "ALLER", "VENIR", "SAVOIR",
	"POUVOIR", "VOULOIR", "DEVOIR", "FALLOIR",
	"HOMME", "FEMME", "ENFANT", "TEMPS", "ANNEE", "JOUR",
	"MILLE", "CENT", "MILLION", "MILLIARD", "PREMIER",
	"GRAND", "PETIT", "BON", "MAUVAIS", "NOUVEAU", "VIEUX",
}

var FrenchFrequencies = map[rune]float64{
	'E': 14.7, 'A': 8.4, 'S': 7.9, 'I': 7.5, 'T': 7.3,
	'N': 7.0, 'R': 6.6, 'U': 6.2, 'L': 5.6, 'O': 5.3,
	'D': 4.2, 'C': 3.5, 'M': 3.2, 'P': 2.8, 'V': 2.2,
	'Q': 1.3, 'G': 1.1, 'F': 1.0, 'H': 0.9, 'B': 0.8,
	'X': 0.5, 'Y': 0.4, 'Z': 0.3, 'J': 0.2, 'K': 0.1,
}

type CrackResult struct {
	Shift       int
	Decrypted   string
	Score       int
	FrenchWords int
}

func (c *CaesarAlgo) BruteForce() []CrackResult {
	var results []CrackResult
	upperText := strings.ToUpper(c.text)

	for shift := 0; shift < 26; shift++ {
		decrypted := decryptCaesar(upperText, shift)
		score, frenchWords := scoreFrench(decrypted)
		results = append(results, CrackResult{
			Shift:       shift,
			Decrypted:   decrypted,
			Score:       score,
			FrenchWords: frenchWords,
		})
	}

	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Score > results[i].Score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	return results
}

func (c *CaesarAlgo) CrackWithDictionary() (string, int) {
	results := c.BruteForce()
	for _, result := range results {
		if result.FrenchWords >= 3 {
			return result.Decrypted, result.Shift
		}
	}
	return results[0].Decrypted, results[0].Shift
}

func (c *CaesarAlgo) CrackWithIC() (string, int) {
	upperText := strings.ToUpper(c.text)
	cleanText := filterLetters(upperText)
	if len(cleanText) < 10 {
		return c.CrackWithDictionary()
	}

	icText := calculateIC(cleanText)

	bestShift := 0
	bestScore := 0.0

	for shift := 0; shift < 26; shift++ {
		decrypted := decryptCaesar(cleanText, shift)
		icDecrypted := calculateIC(decrypted)

		diff := icText - icDecrypted
		if diff < 0 {
			diff = -diff
		}

		if diff < 0.02 {
			score, _ := scoreFrench(decrypted)
			if float64(score) > bestScore {
				bestScore = float64(score)
				bestShift = shift
			}
		}
	}

	return decryptCaesar(upperText, bestShift), bestShift
}

func decryptCaesar(text string, shift int) string {
	result := make([]rune, len(text))
	for i, r := range text {
		if r >= 'A' && r <= 'Z' {
			result[i] = rune((int(r-'A')-shift+26)%26 + 'A')
		} else {
			result[i] = r
		}
	}
	return string(result)
}

func filterLetters(text string) string {
	var result []rune
	for _, r := range text {
		if unicode.IsLetter(r) {
			result = append(result, unicode.ToUpper(r))
		}
	}
	return string(result)
}

func calculateIC(text string) float64 {
	if len(text) < 2 {
		return 0.0
	}

	counts := make(map[rune]int)
	for _, r := range text {
		counts[r]++
	}

	var ic float64
	for _, count := range counts {
		ic += float64(count * (count - 1))
	}

	return ic / (float64(len(text)) * float64(len(text)-1))
}

func scoreFrench(text string) (int, int) {
	words := strings.Fields(text)
	frenchCount := 0
	totalScore := 0

	wordSet := make(map[string]bool)
	for _, w := range FrenchCommonWords {
		wordSet[w] = true
	}

	for _, word := range words {
		if len(word) >= 2 {
			if wordSet[word] {
				frenchCount++
				totalScore += len(word)
			}
			if word[len(word)-1] == 'E' || word[len(word)-1] == 'S' {
				totalScore += 1
			}
		}
	}

	return totalScore, frenchCount
}