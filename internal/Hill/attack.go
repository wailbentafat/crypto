package hill

import (
	"fmt"
)

type AttackResult struct {
	KeyMatrix [][]int
	Message   string
	MatrixSize int
	Success   bool
}

func (h *HillAlgo) KnownPlaintextAttack(knownPlaintext, knownCiphertext string, matrixSize int) (AttackResult, error) {
	plaintext := normalizeText(knownPlaintext)
	ciphertext := normalizeText(knownCiphertext)

	if len(plaintext) < matrixSize*2 || len(ciphertext) < matrixSize*2 {
		return AttackResult{}, fmt.Errorf("insufficient plaintext/ciphertext length")
	}

	blockLen := matrixSize * 2
	numBlocks := len(plaintext) / blockLen

	P := make([][]int, numBlocks)
	for i := 0; i < numBlocks; i++ {
		P[i] = make([]int, matrixSize)
		for j := 0; j < matrixSize; j++ {
			idx := i*blockLen + j*2
			if idx+1 < len(plaintext) {
				P[i][j] = int(plaintext[idx]-'A')*26 + int(plaintext[idx+1]-'A')
			}
		}
	}

	C := make([][]int, numBlocks)
	for i := 0; i < numBlocks; i++ {
		C[i] = make([]int, matrixSize)
		for j := 0; j < matrixSize; j++ {
			idx := i*blockLen + j*2
			if idx+1 < len(ciphertext) {
				C[i][j] = int(ciphertext[idx]-'A')*26 + int(ciphertext[idx+1]-'A')
			}
		}
	}

	P_matrix := make([][]int, matrixSize*numBlocks)
	for i := 0; i < matrixSize*numBlocks; i++ {
		P_matrix[i] = make([]int, matrixSize)
		for j := 0; j < matrixSize; j++ {
			if i < numBlocks {
				P_matrix[i][j] = P[i][j]
			}
		}
	}

	for i := 0; i < numBlocks; i++ {
		row := i + matrixSize
		if row < matrixSize*numBlocks {
			for j := 0; j < matrixSize; j++ {
				P_matrix[row][j] = C[i][j]
			}
		}
	}

	det, err := determinant(P, matrixSize)
	if err != nil {
		return AttackResult{}, fmt.Errorf("matrix is not invertible: %v", err)
	}

	det = ((det % 26) + 26) % 26

	invDet, ok := modularInverse26(det)
	if !ok {
		return AttackResult{}, fmt.Errorf("determinant has no modular inverse")
	}

	adjugate := adjugateMatrix(P, matrixSize)

	key := make([][]int, matrixSize)
	for i := 0; i < matrixSize; i++ {
		key[i] = make([]int, matrixSize)
		for j := 0; j < matrixSize; j++ {
			key[i][j] = (invDet * adjugate[i][j]) % 26
			if key[i][j] < 0 {
				key[i][j] += 26
			}
		}
	}

	result := AttackResult{
		KeyMatrix: key,
		Message:   fmt.Sprintf("Recovered %dx%d key matrix", matrixSize, matrixSize),
		MatrixSize: matrixSize,
		Success:   true,
	}

	return result, nil
}

func (h *HillAlgo) BruteForceMatrix(matrixSize int) []AttackResult {
	var results []AttackResult

	total := 1
	for i := 0; i < matrixSize*matrixSize; i++ {
		total *= 26
	}

	tested := 0
	maxTests := 100000

	for a := 0; a < 26 && tested < maxTests; a++ {
		for b := 0; b < 26 && tested < maxTests; b++ {
			key := [][]int{{a, b}}
			if matrixSize == 2 {
				for c := 0; c < 26 && tested < maxTests; c++ {
					for d := 0; d < 26 && tested < maxTests; d++ {
						key[0] = []int{a, b}
						key = append(key, []int{c, d})

						det := (a*d - b*c) % 26
						if det < 0 {
							det += 26
						}

						if det == 0 || gcdInt(det, 26) != 1 {
							continue
						}

						tested++
						results = append(results, AttackResult{
							KeyMatrix: key,
							MatrixSize: 2,
						})

						key = key[:1]
					}
				}
			}
		}
		if matrixSize > 2 {
			break
		}
	}

	return results
}

func normalizeText(text string) string {
	var result []rune
	for _, r := range text {
		if r >= 'a' && r <= 'z' {
			result = append(result, r-32)
		} else if r >= 'A' && r <= 'Z' {
			result = append(result, r)
		}
	}
	return string(result)
}

func determinant(matrix [][]int, n int) (int, error) {
	if n == 1 {
		return matrix[0][0], nil
	}
	if n == 2 {
		return matrix[0][0]*matrix[1][1] - matrix[0][1]*matrix[1][0], nil
	}

	det := 0
	sign := 1
	for j := 0; j < n; j++ {
		subMatrix := make([][]int, n-1)
		for i := 1; i < n; i++ {
			subMatrix[i-1] = make([]int, n-1)
			for k := 0; k < j; k++ {
				subMatrix[i-1][k] = matrix[i][k]
			}
			for k := j + 1; k < n; k++ {
				subMatrix[i-1][k-1] = matrix[i][k]
			}
		}
		subDet, _ := determinant(subMatrix, n-1)
		det += sign * matrix[0][j] * subDet
		sign = -sign
	}

	return det, nil
}

func adjugateMatrix(matrix [][]int, n int) [][]int {
	if n == 1 {
		return [][]int{{1}}
	}

	adj := make([][]int, n)
	for i := 0; i < n; i++ {
		adj[i] = make([]int, n)
	}

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			subMatrix := make([][]int, n-1)
			for r := 0; r < n-1; r++ {
				subMatrix[r] = make([]int, n-1)
				for c := 0; c < n-1; c++ {
					row := r
					if r >= i {
						row = r + 1
					}
					col := c
					if c >= j {
						col = c + 1
					}
					subMatrix[r][c] = matrix[row][col]
				}
			}
			cofactor, _ := determinant(subMatrix, n-1)
			if (i+j)%2 == 1 {
				cofactor = -cofactor
			}
			adj[j][i] = ((cofactor % 26) + 26) % 26
		}
	}

	return adj
}

func modularInverse26(a int) (int, bool) {
	a = ((a % 26) + 26) % 26
	for x := 1; x < 26; x++ {
		if (a*x)%26 == 1 {
			return x, true
		}
	}
	return 0, false
}

func gcdInt(a, b int) int {
	if b == 0 {
		if a < 0 {
			return -a
		}
		return a
	}
	return gcdInt(b, a%b)
}

func float64abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}