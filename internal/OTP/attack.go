package otp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var EnglishFrequencies = map[byte]float64{
	'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
	'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
	'L': 4.03, 'U': 2.76, 'C': 2.78, 'M': 2.41, 'W': 2.36,
	'F': 2.23, 'Y': 1.97, 'G': 2.02, 'P': 1.93, 'B': 1.49,
	'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
	'Z': 0.07,
}

var CommonWords = []string{
	"THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
	"CAN", "HAD", "HER", "WAS", "ONE", "OUR", "OUT", "DAY",
	"GET", "HAS", "HIM", "HIS", "HOW", "MAN", "NEW", "NOW",
	"OLD", "SEE", "TWO", "WAY", "WHO", "BOY", "DID", "ITS",
	"LET", "PUT", "SAY", "SHE", "TOO", "USE", "DAD", "MOM",
}

type OTPCrackResult struct {
	XORResult    string
	Plaintext1   string
	Plaintext2   string
	Confidence   float64
	CribMatches  int
}

func (o *OTPAlgo) AttackKeyReuse(c1Hex, c2Hex string) (OTPCrackResult, error) {
	xorResult, err := o.XORCiphertexts(c1Hex, c2Hex)
	if err != nil {
		return OTPCrackResult{}, err
	}

	plaintext1, plaintext2, confidence := o.cribDrag(xorResult)

	return OTPCrackResult{
		XORResult:    xorResult,
		Plaintext1:   plaintext1,
		Plaintext2:   plaintext2,
		Confidence:   confidence,
		CribMatches:  countCommonWords(plaintext1) + countCommonWords(plaintext2),
	}, nil
}

func (o *OTPAlgo) cribDrag(xorHex string) (string, string, float64) {
	xorBytes, err := hex.DecodeString(xorHex)
	if err != nil {
		return "", "", 0
	}

	bestPlaintext1 := ""
	bestPlaintext2 := ""
	bestScore := 0.0

	for _, crib := range CommonWords {
		if len(crib) >= 3 && len(crib) <= len(xorBytes) {
			cribBytes := []byte(crib)

			for pos := 0; pos <= len(xorBytes)-len(crib); pos++ {
				key1 := make([]byte, len(xorBytes))
				for i := 0; i < len(cribBytes); i++ {
					key1[pos+i] = cribBytes[i] ^ xorBytes[pos+i]
				}

				p2 := make([]byte, len(xorBytes))
				for i := 0; i < len(xorBytes); i++ {
					p2[i] = xorBytes[i] ^ key1[i]
				}

				score := scoreEnglish(string(p2)) + scoreEnglish(crib)
				if score > bestScore {
					bestScore = score
					bestPlaintext1 = crib
					for i := 0; i < pos; i++ {
						bestPlaintext1 = "?" + bestPlaintext1
					}
					for i := pos + len(crib); i < len(xorBytes); i++ {
						bestPlaintext1 += "?"
					}
					bestPlaintext2 = string(p2)
				}
			}
		}
	}

	confidence := min(bestScore/100.0, 1.0)
	return bestPlaintext1, bestPlaintext2, confidence
}

func (o *OTPAlgo) DecryptKnownKey(ciphertextHex, key string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex ciphertext: %v", err)
	}

	if len(ciphertext) != len(key) {
		return "", fmt.Errorf("key length (%d) must match ciphertext length (%d)", len(key), len(ciphertext))
	}

	keyBytes := []byte(key)
	result := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i++ {
		result[i] = ciphertext[i] ^ keyBytes[i]
	}

	return string(result), nil
}

func (o *OTPAlgo) ExtractXOR(ciphertexts []string) ([]string, error) {
	if len(ciphertexts) < 2 {
		return nil, fmt.Errorf("need at least 2 ciphertexts")
	}

	results := make([]string, 0)
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			xor, err := o.XORCiphertexts(ciphertexts[i], ciphertexts[j])
			if err != nil {
				continue
			}
			results = append(results, xor)
		}
	}

	return results, nil
}

func (o *OTPAlgo) FrequencyAnalysisAttack(ciphertextHex string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex ciphertext: %v", err)
	}

	key := make([]byte, len(ciphertext))
	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i++ {
		for k := 0; k < 256; k++ {
			p := ciphertext[i] ^ byte(k)
			if isPrintable(p) || isSpace(p) {
				key[i] = byte(k)
				plaintext[i] = p
				break
			}
		}
	}

	return string(plaintext), nil
}

func scoreEnglish(text string) float64 {
	upperText := strings.ToUpper(text)
	var score float64

	for _, word := range CommonWords {
		if strings.Contains(upperText, word) {
			score += 10
		}
	}

	upper := []byte(upperText)
	for i, b := range upper {
		if b >= 'A' && b <= 'Z' {
			if freq, ok := EnglishFrequencies[b]; ok {
				score += freq * 0.1
			}
		}
		if i > 0 && upper[i-1] == ' ' && b >= 'A' && b <= 'Z' {
			score += 5
		}
	}

	return score
}

func countCommonWords(text string) int {
	upperText := strings.ToUpper(text)
	count := 0
	for _, word := range CommonWords {
		if strings.Contains(upperText, word) {
			count++
		}
	}
	return count
}

func isPrintable(b byte) bool {
	return (b >= 32 && b <= 126)
}

func isSpace(b byte) bool {
	return b == 9 || b == 10 || b == 13 || b == 32
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}