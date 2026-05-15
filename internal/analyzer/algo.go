package analyzer

import (
	"strings"
	"unicode"
)

// AnalysisResult holds the statistical data of a text.
type AnalysisResult struct {
	Text        string             `json:"text"`
	IC          float64            `json:"ic"`
	Frequencies map[string]float64 `json:"frequencies"`
}

// EnglishFrequencies represents the standard frequency of letters in English.
var EnglishFrequencies = map[string]float64{
	"A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702,
	"F": 2.228, "G": 2.015, "H": 6.094, "I": 6.966, "J": 0.153,
	"K": 0.772, "L": 4.025, "M": 2.406, "N": 6.749, "O": 7.507,
	"P": 1.929, "Q": 0.095, "R": 5.987, "S": 6.327, "T": 9.056,
	"U": 2.758, "V": 0.978, "W": 2.360, "X": 0.150, "Y": 1.974,
	"Z": 0.074,
}

// Analyze calculates frequencies and IC for the given text.
func Analyze(text string) AnalysisResult {
	counts := make(map[rune]int)
	total := 0
	for _, r := range text {
		if unicode.IsLetter(r) {
			r = unicode.ToUpper(r)
			counts[r]++
			total++
		}
	}

	frequencies := make(map[string]float64)
	var icNumerator float64
	for r, count := range counts {
		frequencies[string(r)] = (float64(count) / float64(total)) * 100
		icNumerator += float64(count * (count - 1))
	}

	var ic float64
	if total > 1 {
		ic = icNumerator / (float64(total) * float64(total-1))
	}

	return AnalysisResult{
		Text:        text,
		IC:          ic,
		Frequencies: frequencies,
	}
}

// KasiskiResult holds the results of a Kasiski examination.
type KasiskiResult struct {
	Sequences map[string][]int
	Distances []int
	PossibleLengths []int
}

// KasiskiExamination performs Kasiski examination to estimate key length.
func KasiskiExamination(text string, minLen int) KasiskiResult {
	text = strings.ToUpper(text)
	var filtered []rune
	for _, r := range text {
		if r >= 'A' && r <= 'Z' {
			filtered = append(filtered, r)
		}
	}
	s := string(filtered)

	sequences := make(map[string][]int)
	for i := 0; i <= len(s)-minLen; i++ {
		seq := s[i : i+minLen]
		for j := i + 1; j <= len(s)-minLen; j++ {
			if s[j:j+minLen] == seq {
				sequences[seq] = append(sequences[seq], j-i)
			}
		}
	}

	distanceCounts := make(map[int]int)
	for _, dists := range sequences {
		for _, d := range dists {
			for i := 2; i <= 20; i++ {
				if d%i == 0 {
					distanceCounts[i]++
				}
			}
		}
	}

	// Filter sequences to only those with repeats
	finalSequences := make(map[string][]int)
	for seq, dists := range sequences {
		if len(dists) > 0 {
			finalSequences[seq] = dists
		}
	}

	return KasiskiResult{
		Sequences: finalSequences,
		PossibleLengths: getTopPossibleLengths(distanceCounts),
	}
}

func getTopPossibleLengths(counts map[int]int) []int {
	type kv struct {
		Key   int
		Value int
	}
	var ss []kv
	for k, v := range counts {
		ss = append(ss, kv{k, v})
	}
	// Sort by count descending
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			if ss[i].Value < ss[j].Value {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}

	res := make([]int, 0)
	for i := 0; i < len(ss) && i < 5; i++ {
		if ss[i].Value > 0 {
			res = append(res, ss[i].Key)
		}
	}
	return res
}

// CalculateAvalanche compares two byte slices and returns the percentage of differing bits.
func CalculateAvalanche(b1, b2 []byte) float64 {
	if len(b1) != len(b2) {
		return 0
	}

	diffBits := 0
	totalBits := len(b1) * 8

	for i := 0; i < len(b1); i++ {
		xor := b1[i] ^ b2[i]
		for xor > 0 {
			if xor&1 == 1 {
				diffBits++
			}
			xor >>= 1
		}
	}

	return (float64(diffBits) / float64(totalBits)) * 100
}
