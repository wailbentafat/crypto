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

type WEPResult struct {
	IV          []byte
	FirstByte   byte
	KeyByte     byte
	Correlation float64
}

func (r *RC4Algo) WEPAttack(iv []byte, ciphertext byte) WEPResult {
	keyLen := len(r.state) / 256
	keyBytes := make([]byte, keyLen)
	for ki := 0; ki < keyLen; ki++ {
		for kb := 0; kb < 256; kb++ {
			testKey := make([]byte, keyLen)
			copy(testKey, keyBytes)
			testKey[ki] = byte(kb)
			
			testRC4 := InitRC4(string(testKey))
			i, j := 0, 0
			i = (i + 1) % 256
			j = (j + int(testRC4.state[i])) % 256
			testRC4.state[i], testRC4.state[j] = testRC4.state[j], testRC4.state[i]
			keystreamByte := testRC4.state[(int(testRC4.state[i])+int(testRC4.state[j]))%256]
			
			plaintextByte := ciphertext ^ keystreamByte
			if plaintextByte == 'A' || plaintextByte == 'T' {
				keyBytes[ki] = byte(kb)
				break
			}
		}
	}
	
	return WEPResult{
		IV:          iv,
		FirstByte:   ciphertext,
		KeyByte:     keyBytes[0],
		Correlation: 0.5,
	}
}

func GenerateWeakIVs() [][]byte {
	ivs := make([][]byte, 0)
	for iv := 0; iv < 256; iv++ {
		if iv < 16 || iv == 0xFF {
			ivs = append(ivs, []byte{byte(iv), 0x00, 0x00})
		}
	}
	return ivs
}

func (r *RC4Algo) GenerateKeystream(iv []byte) []byte {
	testRC4 := &RC4Algo{
		state: r.state,
	}
	
	stateCopy := r.state
	testRC4.state = stateCopy
	
	keystream := make([]byte, 256)
	i, j := 0, 0
	
	for k := 0; k < 256; k++ {
		i = (i + 1) % 256
		j = (j + int(testRC4.state[i])) % 256
		testRC4.state[i], testRC4.state[j] = testRC4.state[j], testRC4.state[i]
		keystream[k] = testRC4.state[(int(testRC4.state[i])+int(testRC4.state[j]))%256]
	}
	
	return keystream
}

type BiasResult struct {
	BytePosition int
	BiasedValue  byte
	Probability  float64
}

func (r *RC4Algo) RC4BiasTest(numKeys int) []BiasResult {
	biasCounts := make([]map[byte]int, 256)
	for i := 0; i < 256; i++ {
		biasCounts[i] = make(map[byte]int)
	}
	
	for k := 0; k < numKeys; k++ {
		key := make([]byte, 5)
		for i := range key {
			key[i] = byte(k % 256)
		}
		rc4 := InitRC4(string(key))
		keystream := rc4.GenerateKeystream(nil)
		
		for i := 0; i < 256; i++ {
			biasCounts[i][keystream[i]]++
		}
	}
	
	results := make([]BiasResult, 0)
	expected := float64(numKeys) / 256.0
	
	for i := 0; i < 256; i++ {
		if len(biasCounts[i]) > 0 {
			maxCount := 0
			maxValue := byte(0)
			for v, c := range biasCounts[i] {
				if c > maxCount {
					maxCount = c
					maxValue = v
				}
			}
			prob := float64(maxCount) / float64(numKeys)
			if prob > 0.01 || maxCount > int(expected)*2 {
				results = append(results, BiasResult{
					BytePosition: i,
					BiasedValue:  maxValue,
					Probability:  prob,
				})
			}
		}
	}
	
	return results
}
