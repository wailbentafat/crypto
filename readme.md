# Cryptography Implementation Roadmap – Full Document

## 1. Classical Symmetric Ciphers

1. **Caesar Cipher**

   * **Description:** Simple substitution cipher that shifts each letter by a fixed number.
   * **TODO:**

     * Function: `encrypt_caesar(plaintext, shift)`
     * Function: `decrypt_caesar(ciphertext, shift)`
     * Handle wrap-around for letters.

    2. **Affine Cipher**

    * **Description:** Uses `E(x) = (a*x + b) mod m` for encryption; more secure than Caesar.
    * **TODO:**

        * Function: `encrypt_affine(plaintext, a, b)`
        * Function: `decrypt_affine(ciphertext, a, b)` (requires modular inverse of `a`)

3. **Vigenère Cipher**

   * **Description:** Polyalphabetic cipher using a repeating key word.
   * **TODO:**

     * Function: `encrypt_vigenere(plaintext, key)`
     * Function: `decrypt_vigenere(ciphertext, key)`

4. **Playfair Cipher**

   * **Description:** Encrypts digraphs (pairs of letters) using a 5x5 key matrix.
   * **TODO:**

     * Build 5x5 key matrix.
     * Function: `encrypt_playfair(plaintext, key_matrix)`
     * Function: `decrypt_playfair(ciphertext, key_matrix)`
     * Handle digraph rules and 'I/J' merging.

5. **Hill Cipher**

   * **Description:** Linear algebra-based cipher; encrypts blocks using matrix multiplication modulo 26.
   * **TODO:**

     * Function: `encrypt_hill(plaintext, key_matrix)`
     * Function: `decrypt_hill(ciphertext, key_matrix)` (requires modular matrix inverse)
     * Support 2x2 or 3x3 matrices.

---

## 2. Modern Symmetric Ciphers

1. **RC4**

   * **Description:** Stream cipher using key-scheduling (KSA) and pseudo-random generation (PRGA).
   * **TODO:**

     * Implement `ksa(key)` to initialize state array.
     * Implement `prga(state)` to generate keystream.
     * Function: `encrypt_rc4(plaintext, key)` (XOR keystream).

2. **DES**

   * **Description:** Block cipher (64-bit) using 56-bit key; Feistel structure.
   * **TODO:**

     * Initial and final permutation functions.
     * Implement 16-round Feistel function with expansion, S-box, and permutation.
     * Function: `encrypt_des(plaintext, key)`
     * Function: `decrypt_des(ciphertext, key)`.

3. **AES (Rijndael)**

   * **Description:** Block cipher (128-bit blocks) with key sizes 128/192/256; uses SubBytes, ShiftRows, MixColumns, AddRoundKey.
   * **TODO:**

     * Implement key expansion.
     * Implement SubBytes, ShiftRows, MixColumns, AddRoundKey.
     * Function: `encrypt_aes(plaintext, key)`
     * Function: `decrypt_aes(ciphertext, key)`.

4. **RC6**

   * **Description:** 128-bit block cipher, 20 rounds; uses rotations and modular arithmetic.
   * **TODO:**

     * Implement key expansion.
     * Function: `encrypt_rc6(plaintext, key)`
     * Function: `decrypt_rc6(ciphertext, key)`.

5. **Serpent**

   * **Description:** 32-round block cipher with substitution-permutation network.
   * **TODO:**

     * Implement S-box layer and linear transformations.
     * Function: `encrypt_serpent(plaintext, key)`
     * Function: `decrypt_serpent(ciphertext, key)`.

---

## 3. Key Exchange

1. **Diffie-Hellman**

   * **Description:** Allows two parties to generate a shared secret using modular exponentiation.
   * **TODO:**

     * Generate private and public keys: `private_key, public_key = generate_keys(p, g)`
     * Compute shared secret: `shared_secret = compute_shared_secret(their_public_key, my_private_key, p)`.

---

## 4. Asymmetric / Public-Key Cryptosystems

1. **RSA**

   * **Description:** Based on factoring large primes. Encryption: `c = m^e mod n`, Decryption: `m = c^d mod n`.
   * **TODO:**

     * Generate large primes `p` and `q`.
     * Compute `n = p*q` and totient `phi = (p-1)*(q-1)`.
     * Compute public key `e` and private key `d`.
     * Functions: `encrypt_rsa(m, e, n)` and `decrypt_rsa(c, d, n)`.

2. **ElGamal**

   * **Description:** Based on discrete logarithm problem; uses multiplicative group modulo a prime.
   * **TODO:**

     * Generate prime `p` and generator `g`.
     * Generate keys: `private_key` and `public_key`.
     * Functions: `encrypt_elgamal(m, public_key, g, p)` and `decrypt_elgamal(c, private_key, p)`.

---

## 5. Hash Functions

1. **MD5**

   * **Description:** Produces 128-bit hash; fast but not secure for cryptography.
   * **TODO:**

     * Function: `md5_hash(message)`
     * Implement padding and processing in 512-bit blocks.

2. **SHA-256**

   * **Description:** Produces 256-bit hash; part of SHA-2 family, widely used.
   * **TODO:**

     * Function: `sha256_hash(message)`
     * Implement padding, block processing, and hash computation.
