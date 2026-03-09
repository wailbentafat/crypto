# Crypto CLI - Cryptography Algorithms Implementation

A command-line tool implementing various classical and modern cryptographic algorithms.

## Installation

```bash
cd /path/to/crypto
go build -o crypto ./cmd/main.go
```

## Usage

```bash
./crypto [options] [input]
```

### Global Options

| Flag | Description | Default |
|------|-------------|---------|
| `-a` | Algorithm name | `caesar` |
| `-m` | Mode: encrypt, decrypt, hash, keygen | `encrypt` |
| `-k` | Key for encryption/decryption | - |
| `-i` | Input file | stdin |
| `-o` | Output file | stdout |

### Algorithm-Specific Options

| Algorithm | Additional Flags |
|-----------|-----------------|
| Caesar | `-s` (shift, default: 3) |
| Affine | `-a-param` (a, must be coprime with 26), `-b-param` (b) |
| Vigenere | `-k` (key) |
| Playfair | `-k` (key) |
| Hill | `-k` (key), `-n` (matrix size: 2 or 3) |
| RC4 | `-k` (key) |
| DES | `-k` (key, 8 characters) |
| AES | `-k` (key, 16/24/32 characters) |
| RC6 | `-k` (key) |
| Serpent | `-k` (key) |
| Diffie-Hellman | `-p` (prime), `-g` (generator), `-kf` (key file) |
| RSA | `-bits` (key size), `-pubk` (public key file), `-prvk` (private key file) |
| ElGamal | `-p` (prime), `-g` (generator), `-pubk`, `-prvk` |
| MD5 | `-m hash` |
| SHA256 | `-m hash` |

---

## Algorithms

### Classical Ciphers

#### Caesar Cipher
Simple substitution cipher that shifts each letter by a fixed number.

```bash
# Encrypt
./crypto -a caesar -s 3 "hello"
# Output: khoor

# Decrypt
./crypto -a caesar -s 3 -m decrypt "khoor"
# Output: hello
```

#### Affine Cipher
Uses the formula E(x) = (a*x + b) mod m, where a must be coprime with 26.

```bash
# Encrypt (a=5, b=8)
./crypto -a affine -a-param 5 -b-param 8 "hello"

# Decrypt
./crypto -a affine -a-param 5 -b-param 8 -m decrypt "ciphertext"
```

#### Vigenère Cipher
Polyalphabetic cipher using a repeating keyword.

```bash
# Encrypt
./crypto -a vigenere -k "KEY" "hello"

# Decrypt
./crypto -a vigenere -k "KEY" -m decrypt "ciphertext"
```

#### Playfair Cipher
Encrypts pairs of letters using a 5x5 key matrix. I and J are treated as the same letter.

```bash
# Encrypt
./crypto -a playfair -k "KEYWORD" "hello world"

# Decrypt
./crypto -a playfair -k "KEYWORD" -m decrypt "ciphertext"
```

#### Hill Cipher
Linear algebra-based cipher using matrix multiplication modulo 26.

```bash
# Encrypt (2x2 matrix)
./crypto -a hill -k "GYBNQKURP" -n 2 "hello"

# Encrypt (3x3 matrix)
./crypto -a hill -k "GYBNQKURP" -n 3 "hello"

# Decrypt
./crypto -a hill -k "GYBNQKURP" -n 2 -m decrypt "ciphertext"
```

---

### Modern Symmetric Ciphers

#### RC4
Stream cipher with key scheduling (KSA) and pseudo-random generation (PRGA).

```bash
# Encrypt
./crypto -a rc4 -k "secretkey" "hello world"

# Decrypt
./crypto -a rc4 -k "secretkey" -m decrypt "ciphertext"
```

#### DES
Block cipher (64-bit) with 56-bit key using Feistel structure.

```bash
# Encrypt
./crypto -a des -k "mystring" "hello world"

# Decrypt
./crypto -a des -k "mystring" -m decrypt "ciphertext"
```

#### AES (Rijndael)
Block cipher (128-bit) with key sizes 128/192/256 bits.

```bash
# Encrypt (16-byte key)
./crypto -a aes -k "mysecretkey12345" "hello world"

# Encrypt (24-byte key)
./crypto -a aes -k "mysecretkey123456789012" "hello"

# Encrypt (32-byte key)
./crypto -a aes -k "mysecretkey1234567890123456" "hello"

# Decrypt
./crypto -a aes -k "mysecretkey12345" -m decrypt "ciphertext"
```

#### RC6
128-bit block cipher with 20 rounds using rotations and modular arithmetic.

```bash
# Encrypt
./crypto -a rc6 -k "secretkey12345678" "hello world"

# Decrypt
./crypto -a rc6 -k "secretkey12345678" -m decrypt "ciphertext"
```

#### Serpent
32-round block cipher with substitution-permutation network.

```bash
# Encrypt
./crypto -a serpent -k "mysecretkey1234567" "hello world"

# Decrypt
./crypto -a serpent -k "mysecretkey1234567" -m decrypt "ciphertext"
```

---

### Key Exchange

#### Diffie-Hellman
Allows two parties to generate a shared secret using modular exponentiation.

```bash
# Generate keys (Alice)
./crypto -a dh -p 23 -g 5 -m keygen

# Compute shared secret (Bob, using Alice's public key)
./crypto -a dh -p 23 -g 5 -m encrypt -kf alice_public_key.txt
```

---

### Asymmetric Cryptosystems

#### RSA
Public-key cryptosystem based on factoring large primes.

```bash
# Generate keys
./crypto -a rsa -m keygen -bits 2048

# Encrypt (requires public key N and E)
./crypto -a rsa -m encrypt -k "n_value" -pubk "public.key" "message"

# Decrypt (requires private key D and N)
./crypto -a rsa -m decrypt -k "d_value" -prvk "private.key" "ciphertext"
```

#### ElGamal
Public-key cryptosystem based on discrete logarithm problem.

```bash
# Generate keys
./crypto -a elgamal -p 23 -g 5 -m keygen

# Encrypt
./crypto -a elgamal -p 23 -g 5 -m encrypt -pubk "public.key" "message"

# Decrypt
./crypto -a elgamal -p 23 -g 5 -m decrypt -prvk "private.key" "ciphertext"
```

---

### Hash Functions

#### MD5
Produces 128-bit hash. Note: Not cryptographically secure.

```bash
./crypto -a md5 -m hash "hello"
# Output: 2b98f400c305168cb9e42e6ae1ff0223
```

#### SHA-256
Produces 256-bit hash from SHA-2 family.

```bash
./crypto -a sha256 -m hash "hello"
# Output: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

---

## File Input/Output

```bash
# Read from file
./crypto -a aes -k "key12345678901234" -i input.txt -o output.txt

# Read from stdin
echo "hello" | ./crypto -a caesar -s 3

# Write to file
./crypto -a md5 -m hash "hello" -o hash.txt
```

## Complete Examples

### File Encryption with AES

```bash
# Encrypt a file
./crypto -a aes -k "mysecretkey12345" -i plaintext.txt -o encrypted.bin

# Decrypt the file
./crypto -a aes -k "mysecretkey12345" -m decrypt -i encrypted.bin -o decrypted.txt
```

### Password Hashing

```bash
# Hash a password
./crypto -a sha256 -m hash "mypassword"
```

### Multiple Operations

```bash
# Chain operations
echo "test" | ./crypto -a caesar -s 1 | ./crypto -a caesar -s 2
```

---

## Algorithm Selection Guide

| Use Case | Recommended Algorithm |
|----------|---------------------|
| Learning cryptography | Caesar, Affine, Vigenere |
| Historical interest | Playfair, Hill |
| Stream encryption | RC4 |
| Legacy systems | DES |
| Modern encryption | AES |
| High security | AES-256, Serpent |
| Key exchange | Diffie-Hellman |
| Digital signatures | RSA |
| Hashing (legacy) | MD5 |
| Hashing (modern) | SHA-256 |

---

## Security Notes

- **MD5**: Cryptographically broken, use for checksums only
- **DES**: Considered insecure, use AES instead
- **RC4**: Deprecated, use AES instead
- **Classical ciphers**: For educational purposes only, not secure for real use
