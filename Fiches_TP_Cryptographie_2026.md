# Fiches de Travaux Pratiques — Cryptographie Appliquée
**Niveau :** Ing 3 - Cybersécurité  
**Volume :** 7 TPs  
**Langage :** Python 3.9+ (facultatif)  
**Bibliothèques (facultatif) :** `cryptography`, `hashlib`, `sympy`, `pycryptodome`  
**Prérequis :** Arithmétique modulaire, Algorithmique  
**Évaluation :** Rapport + Code + Vidéo démo  

---

## Architecture Générale des Travaux Pratiques

| N° | Thème principal | Algorithmes / Outils |
| :--- | :--- | :--- |
| **TP 1** | Chiffrement Classique | César, Vigenère, Hill, OTP (Vernam) |
| **TP 2** | Crypto Symétrique Moderne | RC4, DES, AES-128/192/256 + 5 finalistes NIST |
| **TP 3** | Crypto Asymétrique | Diffie-Hellman, RSA, ElGamal, ECC |
| **TP 4** | Fonctions de Hachage | MD5, SHA-256, SHA-512, HMAC |
| **TP 5** | Signatures Numériques | RSA-PSS, ElGamal, DSA, ECDSA |
| **TP 6** | Application Sécurisée | Sockets TCP/UDP, Bluetooth, Wi-Fi, vote électronique |

---

## TP 1 : Chiffrement Classique
* **Objectif :** Implémenter César, Vigenère, Hill et OTP, puis analyser leurs faiblesses.
* **Durée estimée :** 3 h

### Exercice 1.1 — Chiffre de César
1. **Implémentation :** Écrire les fonctions `chiffrer_cesar(texte, k)` et `dechiffrer_cesar(texte, k)` en ignorant les espaces et la casse.
2. **Attaque par force brute :** Tester les 26 clés possibles, afficher toutes les déclinaisons et identifier automatiquement le texte français valide via un dictionnaire de mots courants.
3. **Analyse de fréquences :** Calculer l'indice de coïncidence (IC) du cryptogramme, le comparer à l'IC du français ($pprox 0,074$) et en déduire la clé $k$ sans recourir à la force brute.

### Exercice 1.2 — Chiffre de Vigenère
1. **Implémentation :** Implémenter `chiffrer_vigenere(texte, cle)` et `dechiffrer_vigenere(texte, cle)` où la clé est un mot alphabétique.
2. **Test de Kasiski :** Implémenter la recherche de trigrammes répétés dans le cryptogramme pour estimer la longueur probable de la clé.
3. **Analyse par IC :** Pour chaque décalage $k$ possible, découper le cryptogramme en $k$ sous-séquences, calculer l'IC de chacune et retrouver les lettres de la clé par analyse de fréquences.
4. **Question théorique :** En quoi la longueur de la clé impacte-t-elle la sécurité ? Que se passe-t-il quand $|K| = |M|$ ? (Faire le lien avec l'OTP).

### Exercice 1.3 — Chiffre de Hill
1. **Implémentation ($2	imes2$ et $3	imes3$) :** Mettre en œuvre le chiffrement par blocs de 2 et 3 lettres. Intégrer le calcul de l'inverse modulaire de la matrice clé via la formule $	ext{det}^{-1} 	imes 	ext{adj}(K) \pmod{26}$ après avoir vérifié la validité de la matrice.
2. **Attaque à clair connu :** Implémenter l'attaque sur un exemple concret pour récupérer la clé.
3. **Question théorique :** Pourquoi le chiffre de Hill est-il vulnérable à l'attaque à clair connu, même pour de grandes matrices ?

### Exercice 1.4 — One-Time Pad (Vernam)
1. **Implémentation :** Mettre en œuvre l'OTP (génération d'une clé de même longueur, chiffrement par opération XOR octet à octet, déchiffrer et vérifier la restitution exacte).
2. **Vulnérabilité de réutilisation :** Chiffrer deux messages distincts $M_1$ et $M_2$ avec la même clé $K$. Calculer $C_1 \oplus C_2 = M_1 \oplus M_2$ et montrer comment un attaquant peut en extraire des informations.
3. **Analyse des résultats :** Appliquer des statistiques de langue sur $M_1 \oplus M_2$ pour récupérer partiellement $M_1$ et $M_2$ (attaque par « crib dragging »).
4. **Question théorique :** L'OTP est théoriquement parfait mais pratiquement inutilisable. Citer des obstacles concrets à son déploiement.

---

## TP 2 : Cryptographie Symétrique Moderne
* **Objectif :** Étudier RC4, DES, AES et ses 5 finalistes NIST, leurs modes opératoires et leurs vulnérabilités.

### Exercice 2.1 — RC4 (Chiffrement par flot)
1. **Implémentation :** Implémenter RC4 en deux phases distinctes :
   * **KSA** (Key Scheduling Algorithm) : permutation de l'état $S$ selon la clé.
   * **PRGA** (Pseudo-Random Generation Algorithm) : génération du flux de clé (*keystream*) par échanges successifs dans $S$.
2. **Vulnérabilité WEP :** Générer les *keystreams* pour des vecteurs d'initialisation (IV) faibles (commençant par `0x00`, `0x01`...) et observer la corrélation entre le premier octet du *keystream* et la clé.
3. **Biais statistiques (facultatif) :** Générer 10 000 *keystreams* pour des clés aléatoires, tracer l'histogramme du 2e octet et observer le biais vers 0 (*RC4 bias*), justifiant son bannissement dans TLS 1.3.

### Exercice 2.2 — DES et Triple-DES
1. **DES-ECB et DES-CBC :** Chiffrer/déchiffrer un texte de 128 octets en mode ECB puis CBC (avec un IV aléatoire et un padding PKCS7). Comparer rigoureusement les cryptogrammes obtenus.
2. **Visualisation de la faiblesse ECB :** Chiffrer une image de $64	imes64$ pixels en DES-ECB octet par octet ; reconstituer l'image chiffrée et observer que les structures et motifs visuels restent distinctement visibles.
3. **Triple-DES-CBC :** Chiffrer le même message avec le Triple-DES en mode CBC avec une clé de 24 octets. Mesurer et comparer les temps de chiffrement de DES vs 3DES sur un volume de 1 Mo.

### Exercice 2.3 — AES (Advanced Encryption Standard)
1. **Modes ECB / CBC / CTR :** Chiffrer une même image avec AES-128-ECB, AES-256-CBC et AES-256-CTR. Afficher et commenter les trois images chiffrées (mettre en évidence la fuite de structure en mode ECB).
2. **Effet d'avalanche en CBC :** Modifier un seul bit du vecteur d'initialisation (IV) ; observer la propagation de l'erreur sur l'ensemble des blocs suivants (visualiser le taux de bits différents bloc par bloc).
3. **Vulnérabilité de réutilisation de nonce en CTR :** Chiffrer deux messages $M_1$ et $M_2$ avec le même nonce. Calculer $C_1 \oplus C_2 = M_1 \oplus M_2$ et retrouver partiellement les messages clairs.
4. **Performance (AES-128 vs AES-192 vs AES-256) :** Réaliser un test sur un fichier de 10 Mo. Mesurer le débit (Mo/s) et évaluer l'impact du nombre de tours sur les performances globales.

### Exercice 2.4 — Les 5 Finalistes du Concours AES (NIST 1997-2000)
* **Contexte :** Le NIST a évalué 15 candidats avant de sélectionner 5 finalistes. Rijndael a été officiellement retenu comme standard AES en octobre 2000. Les 4 autres demeurent des alternatives cryptographiques solides.
1. **Étude architecturale :** Pour chacun des 5 finalistes (**Rijndael, Twofish, Serpent, RC6, MARS**), décrire en 3 lignes sa structure interne (réseau de substitution-permutation (SPN) ou schéma de Feistel, taille de bloc, nombre de tours, originalités conceptuelles).
2. **Implémentation comparative :** En utilisant des bibliothèques disponibles, chiffrer le même message de 128 bits avec les 5 algorithmes et comparer leurs cryptogrammes.
3. **Benchmark comparatif :** Mesurer précisément le temps de chiffrement et de déchiffrement de chaque finaliste sur 1 Mo de données aléatoires et tracer un graphique en barres.
4. **Question théorique :** L'algorithme Serpent a obtenu la meilleure note pour la sécurité intrinsèque mais n'a pas été choisi. Quel critère déterminant a fait pencher la balance en faveur de Rijndael ?

---

## TP 3 : Cryptographie Asymétrique
* **Objectif :** Implémenter Diffie-Hellman, RSA, ElGamal et ECC afin d'analyser leur sécurité et leurs performances.
* **Bibliothèques :** `cryptography`, `sympy`, `math`

### Exercice 3.1 — Échange de clés Diffie-Hellman (DH)
1. **Implémentation :** Modéliser le protocole DH. Générer un grand nombre premier $p$ (au minimum 512 bits), choisir un générateur $g$, simuler l'échange complet entre Alice et Bob, et calculer la clé secrète partagée $K$.
2. **Attaque de l'homme du milieu (Man-in-the-Middle - MITM) :** Simuler un attaquant interceptant les échanges entre A et B, substituant ses propres valeurs $A'$ et $B'$, et établissant ainsi deux sessions chiffrées distinctes. Illustrer l'attaque par un schéma textuel accompagné des valeurs et des actions menées.
3. **Contre-mesure :** Ajouter une signature ECDSA des clés publiques échangées pour authentifier mutuellement les entités et bloquer l'attaque MITM.

### Exercice 3.2 — RSA (Rivest-Shamir-Adleman)
1. **Implémentation multi-tailles :** Mettre en œuvre RSA-512, RSA-1024 et RSA-2048 à l'aide d'une bibliothèque. Générer les paires de clés pour chaque longueur, chiffrer une chaîne de 32 octets, déchiffrer et exporter les clés au format standard.
2. **Chiffrement hybride (RSA + AES) :** Générer une clé AES-256 aléatoire, la chiffrer avec RSA, puis chiffrer un fichier de 1 Mo avec AES. Mesurer et comparer le temps total de traitement combiné par rapport à un chiffrement purement asymétrique.
3. **Questions théoriques :** * Pourquoi RSA ne peut-il pas chiffrer directement un message de taille arbitraire ?
   * Qu'apporte le schéma de padding OAEP par rapport au chiffrement RSA de base (*textbook RSA*) ?

### Exercice 3.3 — Chiffrement ElGamal
1. **Implémentation :** Implémenter l'algorithme d'ElGamal : génération de clés (un premier $p > 512$ bits, un générateur $g$, un entier aléatoire privé $x$, et la clé publique $y = g^x \pmod p$), chiffrement et déchiffrer d'un entier $M < p$.
2. **Propriété de non-déterminisme :** Chiffrer l'entier $M = 12345$ et le déchiffrer pour vérifier que $\mathcal{D}(\mathcal{E}(M)) = M$. Répéter l'opération et observer que deux chiffrements distincts du même message donnent des cryptogrammes différents.
3. **Malléabilité :** Démontrer mathématiquement et pratiquement que $\mathcal{E}(M_1) \cdot \mathcal{E}(M_2) = \mathcal{E}(M_1 \cdot M_2 \pmod p)$. À partir d'un cryptogramme $C = (C_1, C_2)$, forger un chiffrement valide pour $2M$ tel que $\mathcal{E}(2M) = (C_1, 2C_2 \pmod p)$ sans connaître ni le message $M$, ni la clé privée $x$.
4. **Comparaison des formats :** Comparer la taille des clés et des blocs chiffrés entre RSA-2048 (chiffré de 256 octets) et ElGamal-2048 (chiffré de 512 octets). Discuter des implications pratiques de ce doublement de taille.

### Exercice 3.4 (Supplémentaire) — Cryptographie sur Courbes Elliptiques (ECC)
* **Contexte :** Forme de la courbe de Weierstrass : $y^2 = x^3 + ax + b \pmod p$. Loi de groupe définie par la méthode de la corde et de la tangente. Problème du logarithme discret sur les courbes elliptiques (ECDLP) : trouver $k$ tel que $Q = kP$ est calculatoirement difficile. Équivalence de sécurité : ECC-256 offre un niveau de sécurité comparable à RSA-3072 (NIST SP 800-57).
1. **Arithmétique sur petits paramètres :** Implémenter l'addition de points et la multiplication scalaire sur la courbe pédagogique $y^2 = x^3 + 7 \pmod{97}$. Vérifier de manière empirique les propriétés structurelles du groupe.
2. **ECDH sur la courbe P-256 :** En utilisant `python-cryptography`, générer les paires de clés pour Alice et Bob, calculer le secret partagé via ECDH, puis dériver une clé symétrique AES-256 à l'aide de SHA-256.
3. **Chiffrement hybride complet :** Implémenter un système de type ECIES simplifié où Alice chiffre un message à destination de Bob en utilisant directement la clé publique de ce dernier.

---

## TP 4 : Fonctions de Hachage Cryptographique
* **Objectif :** Implémenter et analyser les propriétés de sécurité de MD5, SHA-256 et SHA-512.
* **Bibliothèques :** `hashlib` (standard), `hmac`, `cryptography`

### Exercice 4.1 — MD5 (Message Digest 5)
* **Rappel :** Empreinte de sortie de 128 bits. Basé sur la construction de Merkle-Damgård avec 4 tours de 16 opérations logiques ($F, G, H, I$). Des collisions pratiques ont été découvertes dès 2004 (Wang & Yu). Désormais banni pour les applications de sécurité, il reste toléré pour le calcul de sommes de contrôle (*checksums*).
1. **Utilisation pratique :** Calculer le hash MD5 de 5 messages de tailles variées (chaîne vide, un seul octet, 1 Ko, 1 Mo, et un fichier binaire) via `hashlib.md5()`. Confirmer que la taille de l'empreinte en sortie reste invariablement fixée à 128 bits.
2. **Effet d'avalanche :** Modifier un unique bit au sein de chaque message original. Comparer les nouvelles empreintes obtenues bit à bit et vérifier que le taux de variance avoisine les $50\%$.

### Exercice 4.2 — SHA-256 (Secure Hash Algorithm 2)
* **Rappel :** Empreinte de sortie de 256 bits. Fondé sur une construction de Merkle-Damgård utilisant des fonctions de compression opérant sur des blocs de 512 bits, cadencée par 64 constantes injectées ($K[i]$ correspondant aux 32 premiers bits des racines cubiques des 64 premiers nombres premiers). Standard incontournable (TLS, Git, Bitcoin, JWT).
1. **Implémentation de base :** Écrire l'algorithme complet de SHA-256 (gestion du padding Merkle-Damgård, expansion du bloc de message initial, et exécution des 64 tours de compression). Valider rigoureusement l'exactitude de votre code en le confrontant aux résultats de `hashlib.sha256()` sur 10 vecteurs de test officiels.
2. **Scénario de vérification d'intégrité :** Simuler la réception d'une archive Linux. Calculer localement le hash SHA-256 du fichier téléchargé, le confronter au hash officiel publié par la distribution, puis afficher de manière conditionnelle le statut : `[OK]` ou `[CORROMPU]`.

### Exercice 4.3 — SHA-512 et Comparaison Générale
* **Rappel :** SHA-512 produit une empreinte de 512 bits via 80 tours de compression appliqués sur des mots de 64 bits. Il s'avère nativement plus performant et rapide que SHA-256 sur les architectures de processeurs 64 bits. En comparaison, la famille SHA-3 (Keccak) s'appuie sur une construction en éponge, structurellement immune aux attaques par extension de longueur (*length extension attacks*).
1. **Analyse comparative :** Calculer simultanément les empreintes MD5, SHA-256 et SHA-512 d'un même texte. Comparer visuellement la longueur des chaînes, mesurer précisément leurs temps respectifs de calcul et valider l'effet d'avalanche pour chacune de ces fonctions.
2. **Test de charge (Benchmark) :** Exécuter le traitement de calcul de hachage sur un volume massif de 100 Mo de données aléatoires. Déterminer le débit effectif en Mo/s pour MD5, SHA-256 et SHA-512 afin d'isoler la fonction la plus véloce ainsi que la plus lente sur votre propre processeur.

---

## TP 5 : Signatures Numériques
* **Objectif :** Générer et vérifier des signatures numériques avec RSA, ElGamal et DSA, puis étudier les attaques associées.
* **Bibliothèques :** `cryptography`, `pycryptodome`
* **Principe fondamental :**
  * **Signature :** $S = 	ext{Sign}(SK, \mathcal{H}(M))$ à l'aide de la clé privée ($SK$).
  * **Vérification :** $	ext{Verify}(PK, M, S) \longrightarrow \{	ext{Vrai}, 	ext{Faux}\}$ au moyen de la clé publique ($PK$).
  * **Garanties apportées :** Authenticité de l'émetteur, intégrité stricte du message, et non-répudiation.

### Exercice 5.1 — Signature RSA (PKCS#1 v1.5 et PSS)
*(Détails d'implémentation et d'attaques à réaliser selon les directives de l'énoncé général)*

### Exercice 5.2 — Signature ElGamal
*(Mise en œuvre du protocole de signature et étude de la fragilité liée à la réutilisation de l'aléa)*

### Exercice 5.3 — DSA et ECDSA
*(Comparaison des performances et des tailles de signatures entre le standard DSA classique et sa variante sur courbes elliptiques)*

---

## TP 6 : Application — Sécurisation des Communications
* **Objectif :** Développer et orchestrer une application modulaire de communication sécurisée de bout en bout entre deux entités distantes (Alice et Bob).
* **Bibliothèques :** `socket`, `ssl`, `bluetooth` (`pybluez`), `cryptography`, `threading`, `qrcode`
* **Contexte opérationnel :** Deux hôtes doivent échanger des informations au travers d'un canal réseau hostile non sécurisé. Le protocole conçu doit impérativement garantir la **confidentialité** (chiffrement symétrique AES combiné à un échange asymétrique RSA), l'**authenticité** des parties prenantes, l'**intégrité** des trames et l'**anonymat des données** (dans le cadre spécifique du sous-système de vote électronique).

### Exercice 6.1 — Sécurisation par Sockets TCP/IP
Implémentation d'un tunnel sécurisé (similaire à un mini-TLS ou utilisation de wrappers SSL/TLS) sur une socket réseau standard pour chiffrer les flux applicatifs.

### Exercice 6.2 — Sécurisation Bluetooth (RFCOMM)
Transposition des mécanismes de chiffrement et d'authentification sur une liaison de communication sans fil à courte portée en utilisant le protocole RFCOMM.

### Exercice 6.3 — Sécurisation sur Wi-Fi / UDP (Application de chat)
Conception d'une application de messagerie instantanée légère, déconnectée ou en mode broadcast/unicast, s'appuyant sur le protocole UDP avec chiffrement à la volée des datagrammes.

### Exercice 6.4 — Application de Vote Électronique Sécurisé
Mise en œuvre d'un système de scrutin numérique exploitant les propriétés mathématiques de l'**homomorphisme** (par exemple, via le cryptosystème de Paillier ou ElGamal homomorphe). Cela doit permettre l'agrégation et le décompte des bulletins de vote sous leur forme chiffrée, garantissant ainsi le secret absolu du vote tout en offrant une vérificabilité publique du résultat global.
