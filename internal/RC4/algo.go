package rc4

import (
	"encoding/hex"
)

type RC4Algo struct {
	state [256]byte
}

func InitRC4(key string) *RC4Algo {
	keyBytes := []byte(key)

	var state [256]byte
	for i := 0; i < 256; i++ {
		state[i] = byte(i)
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(state[i]) + int(keyBytes[i%len(keyBytes)])) % 256
		state[i], state[j] = state[j], state[i]
	}

	return &RC4Algo{state: state}
}

func (r *RC4Algo) process(data []byte) []byte {
	output := make([]byte, len(data))

	i, j := 0, 0
	for n := 0; n < len(data); n++ {
		i = (i + 1) % 256
		j = (j + int(r.state[i])) % 256
		r.state[i], r.state[j] = r.state[j], r.state[i]
		k := r.state[(int(r.state[i])+int(r.state[j]))%256]
		output[n] = data[n] ^ k
	}

	return output
}

func (r *RC4Algo) Encrypt(plaintext string) string {
	data := []byte(plaintext)
	encrypted := r.process(data)
	return hex.EncodeToString(encrypted)
}

func (r *RC4Algo) Decrypt(ciphertext string) string {
	decoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "Invalid ciphertext"
	}
	decrypted := r.process(decoded)
	return string(decrypted)
}
