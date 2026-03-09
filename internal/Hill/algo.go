package hill

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

type HillAlgo struct {
	matrix     [][]int
	matrixSize int
}

func InitHill(key string, size int) (*HillAlgo, error) {
	if size != 2 && size != 3 {
		return nil, errors.New("matrix size must be 2 or 3")
	}

	key = strings.ToUpper(strings.ReplaceAll(key, " ", ""))
	key = strings.ReplaceAll(key, "J", "I")

	keyNumbers := make([]int, 0)
	for _, c := range key {
		if c >= 'A' && c <= 'Z' {
			num := int(c - 'A')
			if c == 'J' {
				num = 8
			}
			keyNumbers = append(keyNumbers, num)
		}
	}

	if len(keyNumbers) < size*size {
		return nil, errors.New("key must have enough characters for the matrix")
	}

	matrix := make([][]int, size)
	for i := 0; i < size; i++ {
		matrix[i] = make([]int, size)
		for j := 0; j < size; j++ {
			matrix[i][j] = keyNumbers[i*size+j] % 26
		}
	}

	det := matrixDeterminant(matrix)
	det = ((det % 26) + 26) % 26

	if gcd(int(det), 26) != 1 {
		return nil, errors.New("matrix must be invertible modulo 26")
	}

	return &HillAlgo{matrix: matrix, matrixSize: size}, nil
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return int(math.Abs(float64(a)))
}

func matrixDeterminant(m [][]int) int {
	n := len(m)
	if n == 2 {
		return m[0][0]*m[1][1] - m[0][1]*m[1][0]
	}

	det := 0
	for i := 0; i < n; i++ {
		sub := make([][]int, n-1)
		for j := 1; j < n; j++ {
			sub[j-1] = make([]int, n-1)
			for k := 0; k < n-1; k++ {
				if k >= i {
					sub[j-1][k] = m[j][k+1]
				} else {
					sub[j-1][k] = m[j][k]
				}
			}
		}
		sign := int(math.Pow(-1, float64(i)))
		det += sign * m[0][i] * matrixDeterminant(sub)
	}
	return det
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

func (h *HillAlgo) matrixMultiply(vec []int) []int {
	size := h.matrixSize
	result := make([]int, size)

	for i := 0; i < size; i++ {
		sum := 0
		for j := 0; j < size; j++ {
			sum += h.matrix[i][j] * vec[j]
		}
		result[i] = sum % 26
	}

	return result
}

func (h *HillAlgo) Encrypt(plaintext string) string {
	plaintext = strings.ToUpper(strings.ReplaceAll(plaintext, "J", "I"))

	var chars []rune
	for _, c := range plaintext {
		if c >= 'A' && c <= 'Z' {
			chars = append(chars, c)
		}
	}

	for len(chars)%h.matrixSize != 0 {
		chars = append(chars, 'X')
	}

	var result []rune
	for i := 0; i < len(chars); i += h.matrixSize {
		vec := make([]int, h.matrixSize)
		for j := 0; j < h.matrixSize; j++ {
			vec[j] = int(chars[i+j] - 'A')
		}

		encrypted := h.matrixMultiply(vec)

		for j := 0; j < h.matrixSize; j++ {
			result = append(result, rune(encrypted[j]+'A'))
		}
	}

	return string(result)
}

func (h *HillAlgo) inverseMatrix() [][]int {
	size := h.matrixSize

	det := matrixDeterminant(h.matrix)
	det = ((det % 26) + 26) % 26
	detInv := modInverse(det, 26)

	adjugate := make([][]int, size)
	for i := 0; i < size; i++ {
		adjugate[i] = make([]int, size)
		for j := 0; j < size; j++ {
			sub := make([][]int, size-1)
			for k := 0; k < size-1; k++ {
				sub[k] = make([]int, size-1)
			}

			row, col := 0, 0
			for m := 0; m < size; m++ {
				for n := 0; n < size; n++ {
					if m != i && n != j {
						sub[row][col] = h.matrix[m][n]
						col++
						if col == size-1 {
							col = 0
							row++
						}
					}
				}
			}

			cofactor := int(math.Pow(-1, float64(i+j))) * matrixDeterminant(sub)
			adjugate[i][j] = ((cofactor % 26) + 26) % 26
		}
	}

	inv := make([][]int, size)
	for i := 0; i < size; i++ {
		inv[i] = make([]int, size)
		for j := 0; j < size; j++ {
			inv[i][j] = (adjugate[j][i] * detInv) % 26
		}
	}

	return inv
}

func (h *HillAlgo) Decrypt(ciphertext string) string {
	if len(ciphertext)%h.matrixSize != 0 {
		return "Invalid ciphertext length"
	}

	invMatrix := h.inverseMatrix()

	oldMatrix := h.matrix
	h.matrix = invMatrix
	defer func() { h.matrix = oldMatrix }()

	var result []rune
	for i := 0; i < len(ciphertext); i += h.matrixSize {
		vec := make([]int, h.matrixSize)
		for j := 0; j < h.matrixSize; j++ {
			vec[j] = int(ciphertext[i+j] - 'A')
		}

		decrypted := h.matrixMultiply(vec)

		for j := 0; j < h.matrixSize; j++ {
			result = append(result, rune(decrypted[j]+'A'))
		}
	}

	return string(result)
}

func main() {
	h, _ := InitHill("GYBNQKURP", 3)
	fmt.Println(h.Encrypt("HELLO"))
	fmt.Println(h.Decrypt(h.Encrypt("HELLO")))
}
