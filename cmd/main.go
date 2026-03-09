package main

import (
	aes "crypto/internal/AES"
	affine "crypto/internal/Affine"
	caesar "crypto/internal/Caesar"
	des "crypto/internal/DES"
	diffiehellman "crypto/internal/DiffieHellman"
	elgamal "crypto/internal/ElGamal"
	hill "crypto/internal/Hill"
	md5 "crypto/internal/MD5"
	playfair "crypto/internal/Playfair"
	rc4 "crypto/internal/RC4"
	rc6 "crypto/internal/RC6"
	rsa "crypto/internal/RSA"
	sha256 "crypto/internal/SHA256"
	serpent "crypto/internal/Serpent"
	vigenere "crypto/internal/Vigenere"
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	mode       = flag.String("m", "encrypt", "Mode: encrypt, decrypt, hash, keygen")
	algorithm  = flag.String("a", "caesar", "Algorithm: caesar, affine, vigenere, playfair, hill, rc4, des, aes, rc6, serpent, dh, rsa, elgamal, md5, sha256")
	key        = flag.String("k", "", "Key for encryption/decryption")
	keyFile    = flag.String("kf", "", "Key file for key exchange algorithms")
	inputFile  = flag.String("i", "", "Input file (default: stdin)")
	outputFile = flag.String("o", "", "Output file (default: stdout)")
	shift      = flag.Int("s", 3, "Shift value for Caesar")
	aParam     = flag.Int("a-param", 1, "a parameter for Affine cipher (must be coprime with 26)")
	bParam     = flag.Int("b-param", 0, "b parameter for Affine cipher")
	matrixSize = flag.Int("n", 2, "Matrix size for Hill cipher (2 or 3)")
	pubKeyFile = flag.String("pubk", "", "Public key file for RSA/ElGamal")
	prvKeyFile = flag.String("prvk", "", "Private key file for RSA/ElGamal")
	prime      = flag.Int("p", 0, "Prime p for DH/ElGamal")
	generator  = flag.Int("g", 0, "Generator g for DH/ElGamal")
	bits       = flag.Int("bits", 2048, "Key size in bits for RSA")
)

func main() {
	flag.Parse()

	var input string
	if *inputFile != "" {
		data, err := os.ReadFile(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
		input = string(data)
	} else {
		if flag.NArg() > 0 {
			input = strings.Join(flag.Args(), " ")
		} else {
			fmt.Scan(&input)
		}
	}

	var output string

	switch *algorithm {
	case "caesar":
		output = handleCaesar(input, *mode)
	case "affine":
		output = handleAffine(input, *mode)
	case "vigenere":
		output = handleVigenere(input, *mode)
	case "playfair":
		output = handlePlayfair(input, *mode)
	case "hill":
		output = handleHill(input, *mode)
	case "rc4":
		output = handleRC4(input, *mode)
	case "des":
		output = handleDES(input, *mode)
	case "aes":
		output = handleAES(input, *mode)
	case "rc6":
		output = handleRC6(input, *mode)
	case "serpent":
		output = handleSerpent(input, *mode)
	case "dh":
		output = handleDiffieHellman(input, *mode)
	case "rsa":
		output = handleRSA(input, *mode)
	case "elgamal":
		output = handleElGamal(input, *mode)
	case "md5":
		output = handleMD5(input)
	case "sha256":
		output = handleSHA256(input)
	default:
		fmt.Fprintf(os.Stderr, "Unknown algorithm: %s\n", *algorithm)
		os.Exit(1)
	}

	if *outputFile != "" {
		err := os.WriteFile(*outputFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(output)
	}
}

func handleCaesar(input, mode string) string {
	algo := caesar.InitCaesar(*shift)
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleAffine(input, mode string) string {
	algo := affine.InitAffine(*aParam, *bParam)
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleVigenere(input, mode string) string {
	if *key == "" {
		fmt.Fprintf(os.Stderr, "Key required for Vigenere cipher\n")
		os.Exit(1)
	}
	algo := vigenere.InitVigenere(*key)
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handlePlayfair(input, mode string) string {
	if *key == "" {
		fmt.Fprintf(os.Stderr, "Key required for Playfair cipher\n")
		os.Exit(1)
	}
	algo := playfair.InitPlayfair(*key)
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleHill(input, mode string) string {
	if *key == "" {
		fmt.Fprintf(os.Stderr, "Key required for Hill cipher\n")
		os.Exit(1)
	}
	algo, err := hill.InitHill(*key, *matrixSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing Hill cipher: %v\n", err)
		os.Exit(1)
	}
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleRC4(input, mode string) string {
	if *key == "" {
		fmt.Fprintf(os.Stderr, "Key required for RC4\n")
		os.Exit(1)
	}
	algo := rc4.InitRC4(*key)
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleDES(input, mode string) string {
	if *key == "" {
		fmt.Fprintf(os.Stderr, "Key required for DES (8 characters)\n")
		os.Exit(1)
	}
	algo := des.InitDES(*key)
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleAES(input, mode string) string {
	if *key == "" {
		fmt.Fprintf(os.Stderr, "Key required for AES (16, 24, or 32 characters)\n")
		os.Exit(1)
	}
	algo, err := aes.InitAES(*key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing AES: %v\n", err)
		os.Exit(1)
	}
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleRC6(input, mode string) string {
	if *key == "" {
		fmt.Fprintf(os.Stderr, "Key required for RC6\n")
		os.Exit(1)
	}
	algo := rc6.InitRC6(*key)
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleSerpent(input, mode string) string {
	if *key == "" {
		fmt.Fprintf(os.Stderr, "Key required for Serpent\n")
		os.Exit(1)
	}
	algo := serpent.InitSerpent(*key)
	if mode == "encrypt" {
		return algo.Encrypt(input)
	}
	return algo.Decrypt(input)
}

func handleDiffieHellman(input, mode string) string {
	if *prime == 0 || *generator == 0 {
		fmt.Fprintf(os.Stderr, "Prime (-p) and generator (-g) required for Diffie-Hellman\n")
		os.Exit(1)
	}
	algo := diffiehellman.InitDiffieHellman(*prime, *generator)

	if mode == "keygen" {
		return algo.GenerateKeys()
	} else if mode == "encrypt" {
		if *keyFile == "" {
			fmt.Fprintf(os.Stderr, "Other party's public key file (-kf) required\n")
			os.Exit(1)
		}
		return algo.ComputeSharedSecret(*keyFile)
	}
	return ""
}

func handleRSA(input, mode string) string {
	if mode == "keygen" {
		return rsa.GenerateKeys(*bits)
	}

	algo := rsa.InitRSA()

	if mode == "encrypt" {
		if *pubKeyFile == "" || *key == "" {
			fmt.Fprintf(os.Stderr, "Public key file (-pubk) and key ID (-k) required for encryption\n")
			os.Exit(1)
		}
		return algo.Encrypt(input, *pubKeyFile, *key)
	} else if mode == "decrypt" {
		if *prvKeyFile == "" || *key == "" {
			fmt.Fprintf(os.Stderr, "Private key file (-prvk) and key ID (-k) required for decryption\n")
			os.Exit(1)
		}
		return algo.Decrypt(input, *prvKeyFile, *key)
	} else if mode == "hash" {
		return algo.Hash(input)
	}
	return ""
}

func handleElGamal(input, mode string) string {
	if *prime == 0 || *generator == 0 {
		fmt.Fprintf(os.Stderr, "Prime (-p) and generator (-g) required for ElGamal\n")
		os.Exit(1)
	}

	algo := elgamal.InitElGamal(*prime, *generator)

	if mode == "keygen" {
		return algo.GenerateKeys()
	} else if mode == "encrypt" {
		if *pubKeyFile == "" {
			fmt.Fprintf(os.Stderr, "Public key file (-pubk) required for encryption\n")
			os.Exit(1)
		}
		return algo.Encrypt(input, *pubKeyFile)
	} else if mode == "decrypt" {
		if *prvKeyFile == "" {
			fmt.Fprintf(os.Stderr, "Private key file (-prvk) required for decryption\n")
			os.Exit(1)
		}
		return algo.Decrypt(input, *prvKeyFile)
	}
	return ""
}

func handleMD5(input string) string {
	return md5.Hash(input)
}

func handleSHA256(input string) string {
	return sha256.Hash(input)
}
