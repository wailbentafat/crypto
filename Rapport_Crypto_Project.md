# Rapport du Projet de Cryptographie Appliquée

**Projet :** Implémentation d'algorithmes cryptographiques en Go  
**Cours :** Cryptographie Appliquée  
**Niveau :** Ingénierie 3 - Cybersécurité  
**Année :** 2025-2026

---

## Membres de l'équipe

- **Zineb Chennit**
- **Sabrine Bentabal**
- **Wail Bentafat**
- [Votre nom]

---

## 1. Introduction et Contexte

### 1.1 Objectifs du Projet

Ce projet a pour objectif d'implémenter une plateforme complète d'algorithmes cryptographiques couvrant l'ensemble des techniques classiques et modernes de cryptographie. Le projet est développé en langage **Go**, un choix motivé par la performance et la sécurité du langage.

Le projet couvre les 6 travaux pratiques (TP) définis dans le syllabus :
- TP 1 : Chiffrement Classique
- TP 2 : Cryptographie Symétrique Moderne
- TP 3 : Cryptographie Asymétrique
- TP 4 : Fonctions de Hachage
- TP 5 : Signatures Numériques
- TP 6 : Application Sécurisée

### 1.2 Architecture du Projet

L'architecture du projet suit une structure modulaire par paquet Go :

```
crypto/
├── internal/
│   ├── Caesar/          # Chiffrement de César
│   ├── Vigenere/       # Chiffrement de Vigenère
│   ├── Hill/           # Chiffrement de Hill
│   ├── OTP/            # One-Time Pad
│   ├── RC4/            # Chiffrement RC4
│   ├── DES/            # Standard DES
│   ├── AES/            # Advanced Encryption Standard
│   ├── TripleDES/      # Triple DES
│   ├── RSA/            # Cryptographie RSA
│   ├── ElGamal/        # Cryptographie ElGamal
│   ├── ECC/            # Cryptographie sur Courbes Elliptiques
│   ├── DiffieHellman/  # Échange de clés Diffie-Hellman
│   ├── MD5/            # Fonction de hachage MD5
│   ├── SHA256/         # Fonction de hachage SHA-256
│   ├── SHA512/         # Fonction de hachage SHA-512
│   ├── HMAC/           # Code d'authentification HMAC
│   ├── Signature/       # Signatures numériques (RSA, DSA, ECDSA)
│   ├── Socket/         # Communications TCP sécurisées
│   ├── Bluetooth/      # Communications Bluetooth sécurisées
│   ├── Chat/           # Application de chat UDP sécurisée
│   ├── Election/       # Système de vote électronique (Paillier)
│   ├── modes/          # Modes de chiffrement (ECB, CBC, CTR)
│   ├── analyzer/       # Outils d'analyse cryptographique
│   ├── benchmark/      # Mesures de performance
│   ├── MARS/           # Algorithme MARS (finaliste AES)
│   ├── Serpent/        # Algorithme Serpent (finaliste AES)
│   ├── Twofish/        # Algorithme Twofish (finaliste AES)
│   ├── RC6/            # Algorithme RC6 (finaliste AES)
│   ├── Playfair/       # Chiffrement de Playfair
│   ├── Affine/         # Chiffrement affine
│   └── core/           # Constantes et utilitaires communs
└── cmd/                # Point d'entrée des programmes
```

---

## 2. Implémentations par TP

### 2.1 TP 1 : Chiffrement Classique

#### 2.1.1 Chiffrement de César

Le chiffrement de César est une méthode de substitution monoalphabétique où chaque lettre est décalée d'un nombre fixe de positions dans l'alphabet.

**Fichiers :** `internal/Caesar/algo.go`, `internal/Caesar/attack.go`

**Fonctionnalités implémentées :**
- `Encrypt(word string)` : Chiffrement avec décalage
- `Decrypt(word string)` : Déchiffrement
- `BruteForce()` : Attaque par force brute (test des 26 clés)
- `CrackWithDictionary()` : Cassage via dictionnaire français
- `CrackWithIC()` : Cassage via indice de coïncidence

```go
type CaesarAlgo struct {
    decalage int
    text     string
}
```

#### 2.1.2 Chiffrement de Vigenère

Le chiffrement de Vigenère utilise une clé alphabetique pour décalages variables.

**Fichiers :** `internal/Vigenere/algo.go`

**Fonctionnalités :**
- `Encrypt(plaintext string)` : Chiffrement polyalphabétique
- `Decrypt(ciphertext string)` : Déchiffrement

#### 2.1.3 Chiffrement de Hill

Le chiffrement de Hill utilise l'algèbre linéaire avec des matrices modulo 26.

**Fichiers :** `internal/Hill/algo.go`, `internal/Hill/attack.go`

**Fonctionnalités :**
- Support des matrices 2x2 et 3x3
- Calcul de l'inverse modulaire de matrice
- `KnownPlaintextAttack()` : Attaque à clair connu

```go
type HillAlgo struct {
    matrix     [][]int
    matrixSize int
}
```

#### 2.1.4 One-Time Pad (OTP)

Le OTP est le seul chiffrement théoriquement parfait lorsqu'utilisé correctement.

**Fichiers :** `internal/OTP/algo.go`, `internal/OTP/attack.go`

**Fonctionnalités :**
- `Encrypt(plaintext, key)` : XOR bit à bit
- `Decrypt(ciphertextHex, key)` : XOR inverse
- `AttackKeyReuse()` : Attaque par réutilisation de clé
- `cribDrag()` : Crib dragging pour récupérer les messages

### 2.2 TP 2 : Cryptographie Symétrique Moderne

#### 2.2.1 RC4

RC4 est un chiffrement par flot avec deux phases : KSA et PRGA.

**Fichiers :** `internal/RC4/algo.go`

**Fonctionnalités :**
- `InitRC4(key)` : Initialisation KSA
- `Encrypt(plaintext)` : Chiffrement
- `Decrypt(ciphertext)` : Déchiffrement
- `WEPAttack()` : Simulation d'attaque WEP
- `RC4BiasTest()` : Test du biais statistique

```go
type RC4Algo struct {
    state [256]byte
}
```

#### 2.2.2 DES et Triple-DES

DES est un chiffrement par blocs de 64 bits avec une structure de Feistel à 16 tours.

**Fichiers :** `internal/DES/algo.go`, `internal/TripleDES/algo.go`

**Fonctionnalités :**
- Implémentation complète du DES avec S-boxes
- Modes ECB et CBC
- `EncryptImage()` : Visualisation du chiffrement d'image
- `CBCEncryptImage()` : Chiffrement d'image en mode CBC
- Triple-DES avec clé de 24 octets (168 bits)

#### 2.2.3 AES

AES (Rijndael) est le standard de chiffrement symétrique avec des blocs de 128 bits.

**Fichiers :** `internal/AES/algo.go`

**Fonctionnalités :**
- Support des clés 128, 192 et 256 bits
- S-Box complète
- Key expansion
- Fonctions SubBytes, ShiftRows, MixColumns, AddRoundKey

#### 2.2.4 Les 5 Finalistes du NIST

Le projet implémente les 4 autres finalistes du concours AES :

| Algorithme | Structure | Tours | Taille bloc |
|------------|-----------|-------|-------------|
| **MARS** | Type-3 Feistel + S-box | 20 | 128 bits |
| **Serpent** | SPN (Substitution-Permutation) | 32 | 128 bits |
| **Twofish** | Feistel modifiée | 16 | 128 bits |
| **RC6** | Feistel avec rotations | 20 | 128 bits |

### 2.3 TP 3 : Cryptographie Asymétrique

#### 2.3.1 Diffie-Hellman

Permet l'échange de clés sécurisé entre deux parties sans partage préalable.

**Fichiers :** `internal/DiffieHellman/algo.go`, `internal/DiffieHellman/attack.go`

**Fonctionnalités :**
- `InitDiffieHellman(p, g)` : Initialisation
- `GenerateKeys()` : Génération de clés
- `SimulateMITM()` : Simulation d'attaque MITM
- `ComputeDiscreteLog()` : Calcul du logarithme discret

#### 2.3.2 RSA

RSA est basé sur la factorisation de grands nombres premiers.

**Fichiers :** `internal/RSA/algo.go`, `internal/RSA/hybrid.go`

**Fonctionnalités :**
- Génération de clés multi-tailles (512, 1024, 2048 bits)
- `Encrypt()` / `Decrypt()` : Chiffrement/Déchiffrement
- Chiffrement hybride RSA+AES
- Implémentation OAEP (Optimal Asymmetric Encryption Padding)

```go
type RSAAlgo struct {
    n           *big.Int
    e           *big.Int
    d           *big.Int
}
```

#### 2.3.3 ElGamal

Basé sur le problème du logarithme discret.

**Fichiers :** `internal/ElGamal/algo.go`, `internal/ElGamal/attack.go`

**Fonctionnalités :**
- Génération de clés
- `Encrypt()` / `Decrypt()`
- Démonstration de malléabilité
- Propriété homomorphique multiplicative

```go
type ElGamalAlgo struct {
    p          *big.Int
    g          *big.Int
    PrivateKey *big.Int
    PublicKey  *big.Int
}
```

#### 2.3.4 Cryptographie sur Courbes Elliptiques (ECC)

ECC offre une sécurité equivalente à RSA avec des clés plus courtes.

**Fichiers :** `internal/ECC/algo.go`

**Fonctionnalités :**
- Arithmétique des points sur courbes elliptiques
- Addition de points et multiplication scalaire
- Curve P-256 implémentée
- ECDH (Elliptic Curve Diffie-Hellman)
- ECIES (Elliptic Curve Integrated Encryption Scheme)

```go
type Point struct {
    X *big.Int
    Y *big.Int
}

type Curve struct {
    A, B, P *big.Int
    Name    string
}
```

### 2.4 TP 4 : Fonctions de Hachage

#### 2.4.1 MD5

MD5 produit une empreinte de 128 bits. Bien que cassé, il reste utile pour les sommes de contrôle.

**Fichiers :** `internal/MD5/algo.go`

**Fonctionnalités :**
- Hachage de messages de toute taille
- Validation de l'effet d'avalanche

#### 2.4.2 SHA-256

SHA-256 est le standard le plus utilisé pour le hachage.

**Fichiers :** `internal/SHA256/algo.go`

**Fonctionnalités :**
- Implémentation complète
- 64 tours de compression
- Validation avec vecteurs de test
- Effet d'avalanche vérifié

#### 2.4.3 SHA-512

SHA-512 fonctionne sur des mots de 64 bits avec 80 tours.

**Fichiers :** `internal/SHA512/algo.go`

**Fonctionnalités :**
- Hachage 512 bits
- Plus performant sur architecture 64 bits
- Comparaison avec SHA-256

#### 2.4.4 HMAC

HMAC combine une clé secrète avec une fonction de hachage.

**Fichiers :** `internal/HMAC/algo.go`

**Fonctionnalités :**
- HMAC-SHA256
- HMAC-SHA512
- `Sign()` / `Verify()`

### 2.5 TP 5 : Signatures Numériques

#### 2.5.1 Signature RSA

**Fichiers :** `internal/Signature/RSA.go`

**Fonctionnalités :**
- Signature et vérification avec RSA

#### 2.5.2 DSA

Standard américain pour les signatures numériques.

**Fichiers :** `internal/Signature/DSA.go`

**Fonctionnalités :**
- Génération de paramètres p, q, g
- Signature et vérification

#### 2.5.3 ECDSA

Signature sur courbes elliptiques.

**Fichiers :** `internal/Signature/ECDSA.go`

**Fonctionnalités :**
- Support des courbes P-224, P-256, P-384, P-521
- Signature et vérification

#### 2.5.4 Signature ElGamal

**Fichiers :** `internal/Signature/ElGamal.go`

### 2.6 TP 6 : Applications Sécurisées

#### 2.6.1 Socket TCP Sécurisée

**Fichiers :** `internal/Socket/secure.go`

**Fonctionnalités :**
- Implémentation TLS 1.2
- Chiffrement AES-256-GCM
- ECDHE pour l'échange de clés

#### 2.6.2 Bluetooth Sécurisé

**Fichiers :** `internal/Bluetooth/secure.go`

**Fonctionnalités :**
- RFCOMM chiffré
- Dérivation de clé de liaison

#### 2.6.3 Chat UDP Sécurisé

**Fichiers :** `internal/Chat/udp.go`

**Fonctionnalités :**
- Chiffrement AES-256-CBC
- HMAC-SHA256 pour l'intégrité

#### 2.6.4 Vote Électronique

**Fichiers :** `internal/Election/paillier.go`

**Fonctionnalités :**
- Cryptosystème de Paillier (homomorphique additif)
- `HomomorphicAdd()` : Addition de votes chiffrés
- `TallyVotes()` : Décompte sans déchiffrement individuel

---

## 3. Outils d'Analyse

### 3.1 Analyse de Fréquence

**Fichiers :** `internal/analyzer/algo.go`

- Calcul de l'indice de coïncidence (IC)
- Analyse de fréquence des lettres
- Comparaison avec les fréquences françaises/anglaises

### 3.2 Test de Kasiski

Permet d'estimer la longueur de la clé pour Vigenère.

```go
type KasiskiResult struct {
    Sequences      map[string][]int
    PossibleLengths []int
}
```

### 3.3 Effet d'Avalanche

Mesure la propagation des changements dans les fonctions de hachage.

---

## 4. Mesures de Performance

**Fichiers :** `internal/benchmark/algo.go`

Le module benchmark permet de mesurer :
- Temps de hachage (MD5, SHA-256, SHA-512)
- Temps de chiffrement DES vs 3DES
- Débit de chiffrement pour différentes tailles de clés
- Comparaison des modes AES (ECB, CBC, CTR)

---

## 5. Conclusions et Perspectives

### 5.1 Résumé

Ce projet a permis d'implémenter une plateforme complète de cryptographie couvrant :

- ✅ 4 chiffrements classiques (César, Vigenère, Hill, OTP)
- ✅ 8 chiffrements modernes (RC4, DES, AES, MARS, Serpent, Twofish, RC6, TripleDES)
- ✅ 4 systèmes asymétriques (RSA, ElGamal, ECC, Diffie-Hellman)
- ✅ 4 fonctions de hachage (MD5, SHA-256, SHA-512, HMAC)
- ✅ 4 types de signatures (RSA, DSA, ECDSA, ElGamal)
- ✅ 4 applications sécurisées (Socket, Bluetooth, Chat, Vote)

### 5.2 Compétences Développées

- Compréhension profonde des algorithmes cryptographiques
- Implémentation en langage Go
- Analyse des vulnérabilités et attaques
- Programmation sécurisé

### 5.3 Améliorations Possibles

- Ajout de tests unitaires pour chaque algorithme
- Interface utilisateur graphique
- Implémentation de davantage d'attaques cryptographiques
- Support de plus de courbes elliptiques

---

## Annexe : Structure des Paquets

| Paquet | Description |
|--------|-------------|
| `caesar` | Chiffrement de César |
| `vigenere` | Chiffrement de Vigenère |
| `hill` | Chiffrement de Hill |
| `otp` | One-Time Pad |
| `rc4` | Chiffrement RC4 |
| `des` | Standard DES |
| `aes` | Advanced Encryption Standard |
| `tripledes` | Triple DES |
| `mars` | Algorithme MARS |
| `serpent` | Algorithme Serpent |
| `twofish` | Algorithme Twofish |
| `rc6` | Algorithme RC6 |
| `diffiehellman` | Échange de clés DH |
| `rsa` | Cryptographie RSA |
| `elgamal` | Cryptographie ElGamal |
| `ecc` | Cryptographie sur courbes elliptiques |
| `md5` | Fonction de hachage MD5 |
| `sha256` | Fonction de hachage SHA-256 |
| `sha512` | Fonction de hachage SHA-512 |
| `hmac` | Code d'authentification HMAC |
| `signature` | Signatures numériques |
| `socket` | Communications TCP sécurisées |
| `bluetooth` | Communications Bluetooth |
| `chat` | Application de chat UDP |
| `election` | Système de vote électronique |
| `modes` | Modes de chiffrement (ECB/CBC/CTR) |
| `analyzer` | Outils d'analyse |
| `benchmark` | Mesures de performance |

---

**Date :** Mai 2026  
**École :** [Nom de l'école]  
**Département :** Cybersécurité