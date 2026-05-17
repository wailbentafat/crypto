package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	internalaes "crypto/internal/AES"
	"crypto/internal/Caesar"
	"crypto/internal/DiffieHellman"
	"crypto/internal/ElGamal"
	"crypto/internal/Hill"
	"crypto/internal/OTP"
	"crypto/internal/Vigenere"
	"crypto/internal/analyzer"
	"crypto/md5"
	"crypto/sha512"
)

// PageData represents the data passed to templates.
type PageData struct {
	Title         string
	ActiveTab     string
	ActiveSubTab  string
	Result        *analyzer.AnalysisResult
	Error         string
	InputText     string
	Algorithm     string
	Mode          string
	Key           string
	Shift         int
	MatrixSize    int
	StandardFreq  map[string]float64
	Kasiski       *analyzer.KasiskiResult
	CribResult    string
	// TP2
	ECBImage      string
	CBCImage      string
	OriginalImage string
	Avalanche     float64
	Benchmarks    map[string]float64
	// TP3
	DHResult        map[string]interface{}
	MitMActive      bool
	UseSignatures   bool
	HybridStep      int
	RSAKeys         *RSAKeyPair
	HybridBenchmark *BenchmarkResult
	ElGamalResult   *ElGamalEncryptResult
	ElGamalForge    *ElGamalForgeResult
	ECCResult       *ECCResult
	ECDHResult      *ECDHResult
	ECDHAESKey      string
	// TP4
	Hashes   map[string]string
	HashAval float64
	// TP6
	ChatLog []string
	VoteRes map[string]int
}

type RSAKeyPair struct {
	PublicN  string
	PrivateD string
}

type BenchmarkResult struct {
	Hybrid float64
	RSA    float64
}

type ElGamalEncryptResult struct {
	p    string
	g    string
	C1_1 string
	C2_1 string
	C1_2 string
	C2_2 string
}

type ElGamalForgeResult struct {
	OriginalMsg string
	ForgedMsg   string
}

type ECCResult struct {
	Qx   string
	Qy   string
	Logs []string
}

type ECDHResult struct {
	AlicePrivate string
	AlicePublicX string
	AlicePublicY string
	BobPrivate   string
	BobPublicX   string
	BobPublicY   string
	SharedSecret string
}

var templates = template.Must(template.ParseGlob("templates/*.html"))
var chatLog []string

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/tp1", http.StatusSeeOther)
}

// --- TP 1 Handlers ---

func TP1Handler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:        "TP 1: Classical Cryptanalysis",
		ActiveTab:    "tp1",
		StandardFreq: analyzer.EnglishFrequencies,
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func AnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp1", http.StatusSeeOther)
		return
	}

	inputText := r.FormValue("input_text")
	algoType := r.FormValue("algorithm")
	mode := r.FormValue("mode")
	key := r.FormValue("key")
	shiftStr := r.FormValue("shift")
	matrixSizeStr := r.FormValue("matrix_size")

	data := PageData{
		Title:        "TP 1: Classical Cryptanalysis",
		ActiveTab:    "tp1",
		InputText:    inputText,
		Algorithm:    algoType,
		Mode:         mode,
		Key:          key,
		StandardFreq: analyzer.EnglishFrequencies,
	}

	var resultText string
	switch algoType {
	case "caesar":
		shift, _ := strconv.Atoi(shiftStr)
		data.Shift = shift
		algo := caesar.InitCaesar(shift)
		if mode == "encrypt" {
			resultText = algo.Encrypt(inputText)
		} else {
			resultText = algo.Decrypt(inputText)
		}
	case "vigenere":
		if key == "" {
			data.Error = "Key required for Vigenère"
			templates.ExecuteTemplate(w, "base.html", data)
			return
		}
		algo := vigenere.InitVigenere(key)
		if mode == "encrypt" {
			resultText = algo.Encrypt(inputText)
		} else {
			resultText = algo.Decrypt(inputText)
		}
	case "hill":
		if key == "" {
			data.Error = "Key required for Hill"
			templates.ExecuteTemplate(w, "base.html", data)
			return
		}
		size, _ := strconv.Atoi(matrixSizeStr)
		data.MatrixSize = size
		algo, err := hill.InitHill(key, size)
		if err != nil {
			data.Error = err.Error()
			templates.ExecuteTemplate(w, "base.html", data)
			return
		}
		if mode == "encrypt" {
			resultText = algo.Encrypt(inputText)
		} else {
			resultText = algo.Decrypt(inputText)
		}
	case "otp":
		if key == "" {
			data.Error = "Key required for OTP"
			templates.ExecuteTemplate(w, "base.html", data)
			return
		}
		algo := otp.InitOTP()
		var err error
		if mode == "encrypt" {
			resultText, err = algo.Encrypt(inputText, key)
		} else {
			resultText, err = algo.Decrypt(inputText, key)
		}
		if err != nil {
			data.Error = err.Error()
			templates.ExecuteTemplate(w, "base.html", data)
			return
		}
	default:
		resultText = inputText
	}

	analysis := analyzer.Analyze(resultText)
	data.Result = &analysis

	if algoType == "vigenere" || algoType == "none" {
		kasiski := analyzer.KasiskiExamination(resultText, 3)
		data.Kasiski = &kasiski
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

func CribHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp1", http.StatusSeeOther)
		return
	}

	c1 := r.FormValue("c1")
	c2 := r.FormValue("c2")

	data := PageData{
		Title:     "TP 1: Classical Cryptanalysis",
		ActiveTab: "tp1",
	}

	algo := otp.InitOTP()
	res, err := algo.XORCiphertexts(c1, c2)
	if err != nil {
		data.Error = err.Error()
	} else {
		data.CribResult = res
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

// --- TP 2 Handlers ---

func TP2Handler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:     "TP 2: Symmetric Lab & Benchmarking",
		ActiveTab: "tp2",
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func ImageUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp2", http.StatusSeeOther)
		return
	}

	file, _, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Error uploading file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	imgData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	if len(imgData) < 8 {
		http.Error(w, "Invalid image file", http.StatusBadRequest)
		return
	}

	if string(imgData[:8]) == "\x89PNG\r\n\x1a\n" {
		log.Printf("PNG format detected")

		timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
		tmpDir := os.TempDir()
		origPath := tmpDir + "/orig_" + timestamp + ".png"
		ecbPath := tmpDir + "/ecb_" + timestamp + ".bmp"
		cbcPath := tmpDir + "/cbc_" + timestamp + ".bmp"

		os.WriteFile(origPath, imgData, 0644)
		log.Printf("Saved original to %s", origPath)

		aesAlgo, _ := internalaes.InitAES("mysecretkey12345")

		pixelData := imgData[8:]
		paddedPixels := make([]byte, ((len(pixelData)/16)+1)*16)
		copy(paddedPixels, pixelData)

		ecbPixels := aesAlgo.EncryptECB(paddedPixels)
		cbcPixels := aesAlgo.EncryptCBC(paddedPixels, make([]byte, 16))

		width := 256
		height := len(ecbPixels) / width
		if height == 0 {
			height = 1
		}
		if height > 1024 {
			height = 1024
		}

		bmpHeader := createBMPHeader(width, height)
		ecbData := ecbPixels[:width*height]
		cbcData := cbcPixels[:width*height]

		ecbFull := make([]byte, 0, len(bmpHeader)+len(ecbData))
		ecbFull = append(ecbFull, bmpHeader...)
		ecbFull = append(ecbFull, ecbData...)

		cbcFull := make([]byte, 0, len(bmpHeader)+len(cbcData))
		cbcFull = append(cbcFull, bmpHeader...)
		cbcFull = append(cbcFull, cbcData...)

		os.WriteFile(ecbPath, ecbFull, 0644)
		os.WriteFile(cbcPath, cbcFull, 0644)
		log.Printf("Saved ECB to %s, CBC to %s", ecbPath, cbcPath)

		pageData := PageData{
			Title:         "TP 2: Symmetric Lab & Benchmarking",
			ActiveTab:     "tp2",
			OriginalImage: "/tp2/img/orig_" + timestamp + ".png",
			ECBImage:      "/tp2/img/ecb_" + timestamp + ".bmp",
			CBCImage:      "/tp2/img/cbc_" + timestamp + ".bmp",
		}

		templates.ExecuteTemplate(w, "base.html", pageData)
		return
	}

	http.Error(w, "Please upload a PNG file", http.StatusBadRequest)
}

func BenchmarkHandler(w http.ResponseWriter, r *http.Request) {
	payload := make([]byte, 1024*1024)
	key := "1234567890123456"

	benchmarks := make(map[string]float64)

	aesAlgo, _ := internalaes.InitAES(key)
	start := time.Now()
	aesAlgo.EncryptECB(payload)
	benchmarks["AES"] = float64(time.Since(start).Milliseconds())

	data := PageData{
		Title:      "TP 2: Symmetric Lab & Benchmarking",
		ActiveTab:  "tp2",
		Benchmarks: benchmarks,
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

func AvalancheHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp2", http.StatusSeeOther)
		return
	}

	inputText := r.FormValue("input_text")
	if inputText == "" {
		inputText = "Hello World 1234"
	}
	for len(inputText)%16 != 0 {
		inputText += " "
	}

	data1 := []byte(inputText)
	data2 := make([]byte, len(data1))
	copy(data2, data1)
	if len(data2) > 0 {
		data2[0] ^= 1
	}

	aesAlgo, _ := internalaes.InitAES("1234567890123456")
	enc1 := aesAlgo.EncryptECB(data1)
	enc2 := aesAlgo.EncryptECB(data2)

	avalanche := analyzer.CalculateAvalanche(enc1, enc2)

	pageData := PageData{
		Title:     "TP 2: Symmetric Lab & Benchmarking",
		ActiveTab: "tp2",
		Avalanche: avalanche,
	}

	templates.ExecuteTemplate(w, "base.html", pageData)
}

// --- TP 3 Handlers ---

func TP3Handler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:        "TP 3: Asymmetric & MitM Lab",
		ActiveTab:    "tp3",
		ActiveSubTab: "dh",
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func TP3TabHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		tab := r.FormValue("tab")
		if tab != "" {
			data := PageData{
				Title:        "TP 3: Asymmetric & MitM Lab",
				ActiveTab:    "tp3",
				ActiveSubTab: tab,
			}
			templates.ExecuteTemplate(w, "base.html", data)
			return
		}
	}
	http.Redirect(w, r, "/tp3", http.StatusSeeOther)
}

func DHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	pStr := r.FormValue("p")
	gStr := r.FormValue("g")
	mitm := r.FormValue("mitm") == "on"
	useSigs := r.FormValue("signatures") == "on"

	p, _ := new(big.Int).SetString(pStr, 10)
	g, _ := new(big.Int).SetString(gStr, 10)

	if p == nil || g == nil {
		p = big.NewInt(23)
		g = big.NewInt(5)
	}

	dh := diffiehellman.InitDiffieHellman(23, 5)

	var result map[string]interface{}

	if mitm {
		result = runDHWithMitM(dh, useSigs)
	} else {
		result = runDHSecure(dh, useSigs)
	}

	data := PageData{
		Title:         "TP 3: Asymmetric & MitM Lab",
		ActiveTab:     "tp3",
		ActiveSubTab:  "dh",
		DHResult:      result,
		MitMActive:    mitm,
		UseSignatures: useSigs,
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

func DHLargeHandler(w http.ResponseWriter, r *http.Request) {
	p, _ := rand.Prime(rand.Reader, 512)
	g := big.NewInt(2)

	dh := &diffiehellman.DiffieHellmanAlgo{
		P: p,
		G: g,
	}

	result := runDHSecure(dh, false)

	data := PageData{
		Title:        "TP 3: Asymmetric & MitM Lab",
		ActiveTab:    "tp3",
		ActiveSubTab: "dh",
		DHResult:     result,
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

func runDHSecure(dh *diffiehellman.DiffieHellmanAlgo, withSigs bool) map[string]interface{} {
	p := dh.GeneratePrimeAndGenerator(512)
	dh = diffiehellman.InitDiffieHellman(int(p.BitLen()), 2)

	alicePriv, _ := rand.Int(rand.Reader, dh.P)
	alicePriv.Add(alicePriv, big.NewInt(2))
	alicePub := new(big.Int).Exp(dh.G, alicePriv, dh.P)

	bobPriv, _ := rand.Int(rand.Reader, dh.P)
	bobPriv.Add(bobPriv, big.NewInt(2))
	bobPub := new(big.Int).Exp(dh.G, bobPriv, dh.P)

	sharedAlice := new(big.Int).Exp(bobPub, alicePriv, dh.P)
	sharedBob := new(big.Int).Exp(alicePub, bobPriv, dh.P)

	aliceStr := sharedAlice.String()
	bobStr := sharedBob.String()
	if len(aliceStr) > 20 {
		aliceStr = aliceStr[:20]
	}
	if len(bobStr) > 20 {
		bobStr = bobStr[:20]
	}

	logs := []string{
		fmt.Sprintf("DH with p=%d-bit prime", p.BitLen()),
		fmt.Sprintf("Alice computes: A = g^a mod p"),
		fmt.Sprintf("Bob computes: B = g^b mod p"),
		fmt.Sprintf("Alice shared secret: %s...", aliceStr),
		fmt.Sprintf("Bob shared secret: %s...", bobStr),
	}

	if withSigs {
		logs = append(logs, "ECDSA signatures would secure this exchange")
	}

	result := map[string]interface{}{
		"p":    dh.P.String(),
		"g":    dh.G.String(),
		"Alice": map[string]string{
			"Private": alicePriv.String(),
			"Public":  alicePub.String(),
		},
		"Bob": map[string]string{
			"Private": bobPriv.String(),
			"Public":  bobPub.String(),
		},
		"s_alice": sharedAlice.String(),
		"s_bob":   sharedBob.String(),
		"Secure":  withSigs,
		"Logs":    logs,
	}

	return result
}

func runDHWithMitM(dh *diffiehellman.DiffieHellmanAlgo, withSigs bool) map[string]interface{} {
	p := dh.GeneratePrimeAndGenerator(512)
	dh = diffiehellman.InitDiffieHellman(int(p.BitLen()), 2)

	alicePriv, _ := rand.Int(rand.Reader, dh.P)
	alicePriv.Add(alicePriv, big.NewInt(2))
	alicePub := new(big.Int).Exp(dh.G, alicePriv, dh.P)

	bobPriv, _ := rand.Int(rand.Reader, dh.P)
	bobPriv.Add(bobPriv, big.NewInt(2))
	bobPub := new(big.Int).Exp(dh.G, bobPriv, dh.P)

	malloryPriv, _ := rand.Int(rand.Reader, dh.P)
	malloryPriv.Add(malloryPriv, big.NewInt(2))
	malloryPub := new(big.Int).Exp(dh.G, malloryPriv, dh.P)

	s_alice := new(big.Int).Exp(malloryPub, alicePriv, dh.P)
	s_bob := new(big.Int).Exp(malloryPub, bobPriv, dh.P)
	s_mal_alice := new(big.Int).Exp(alicePub, malloryPriv, dh.P)
	s_mal_bob := new(big.Int).Exp(bobPub, malloryPriv, dh.P)

	aliceMStr := s_alice.String()
	bobMStr := s_bob.String()
	if len(aliceMStr) > 20 {
		aliceMStr = aliceMStr[:20]
	}
	if len(bobMStr) > 20 {
		bobMStr = bobMStr[:20]
	}

	logs := []string{
		"⚠️ MITM ATTACK IN PROGRESS",
		"Mallory intercepts A from Alice",
		"Mallory intercepts B from Bob",
		"Mallory replaces both with M = g^m mod p",
		fmt.Sprintf("Alice computes: s = M^a = %s...", aliceMStr),
		fmt.Sprintf("Bob computes: s = M^b = %s...", bobMStr),
		"🚨 Mallory can now decrypt all traffic!",
	}

	if withSigs {
		logs = append(logs, "✓ ECDSA signatures would prevent this attack!")
	}

	result := map[string]interface{}{
		"p":    dh.P.String(),
		"g":    dh.G.String(),
		"Alice": map[string]string{
			"Private": alicePriv.String(),
			"Public":  alicePub.String(),
		},
		"Bob": map[string]string{
			"Private": bobPriv.String(),
			"Public":  bobPub.String(),
		},
		"Mallory": map[string]string{
			"Private": malloryPriv.String(),
			"Public":  malloryPub.String(),
		},
		"s_alice":  s_alice.String(),
		"s_bob":    s_bob.String(),
		"s_malice": s_mal_alice.String(),
		"s_mbob":   s_mal_bob.String(),
		"Secure":   withSigs,
		"Logs":     logs,
	}

	return result
}

// RSA Key Generation
func RSAKeyGenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	bits, _ := strconv.Atoi(r.FormValue("bits"))
	if bits == 0 {
		bits = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Printf("RSA keygen error: %v", err)
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	data := PageData{
		Title:        "TP 3: Asymmetric & MitM Lab",
		ActiveTab:    "tp3",
		ActiveSubTab: "hybrid",
		RSAKeys: &RSAKeyPair{
			PublicN:  privateKey.PublicKey.N.String(),
			PrivateD: privateKey.D.String(),
		},
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

// Hybrid Encryption
func HybridEncryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}
	defer file.Close()

	fileData, _ := io.ReadAll(file)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	block, _ := aes.NewCipher(sessionKey)
	iv := make([]byte, 16)
	block.Encrypt(iv, iv)
	stream := cipher.NewCTR(block, iv)
	encryptedFile := make([]byte, len(fileData))
	stream.XORKeyStream(encryptedFile, fileData)

	pubKeyN := r.FormValue("pubkey")
	if pubKeyN == "" {
		pubKeyN = "0"
	}

	n, _ := new(big.Int).SetString(pubKeyN, 10)
	if n == nil || n.BitLen() < 64 {
		n = big.NewInt(0)
	}

	var wrappedKey []byte
	if n.BitLen() > 0 {
		pubKey := &rsa.PublicKey{N: n, E: 65537}
		oaepLabel := []byte("")
		_ = oaepLabel
		wrappedKey, _ = rsa.EncryptPKCS1v15(rand.Reader, pubKey, sessionKey)
	} else {
		wrappedKey = sessionKey
	}

	tmpDir := os.TempDir()
	encFilePath := tmpDir + "/hybrid_encrypted_" + fmt.Sprintf("%d", time.Now().UnixNano())
	wrappedKeyPath := tmpDir + "/hybrid_key_" + fmt.Sprintf("%d", time.Now().UnixNano())

	os.WriteFile(encFilePath, encryptedFile, 0644)
	os.WriteFile(wrappedKeyPath, wrappedKey, 0644)

	data := PageData{
		Title:         "TP 3: Asymmetric & MitM Lab",
		ActiveTab:     "tp3",
		ActiveSubTab:  "hybrid",
		InputText:     "File encrypted! Encrypted: " + encFilePath + ", Key: " + wrappedKeyPath,
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

// Hybrid Decrypt
func HybridDecryptHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/tp3", http.StatusSeeOther)
}

// Hybrid Benchmark
func HybridBenchmarkHandler(w http.ResponseWriter, r *http.Request) {
	payload := make([]byte, 1024*1024)
	rand.Read(payload)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	start := time.Now()
	block, _ := aes.NewCipher(sessionKey)
	iv := make([]byte, 16)
	block.Encrypt(iv, iv)
	stream := cipher.NewCTR(block, iv)
	encrypted := make([]byte, len(payload))
	stream.XORKeyStream(encrypted, payload)
	hybridTime := float64(time.Since(start).Milliseconds())

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := privKey.PublicKey

	start = time.Now()
	_, _ = rsa.EncryptPKCS1v15(rand.Reader, &pubKey, payload)
	rsaTime := float64(time.Since(start).Milliseconds())

	data := PageData{
		Title:         "TP 3: Asymmetric & MitM Lab",
		ActiveTab:     "tp3",
		ActiveSubTab:  "hybrid",
		HybridBenchmark: &BenchmarkResult{
			Hybrid: hybridTime,
			RSA:    rsaTime,
		},
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

// ElGamal Encrypt (Non-determinism)
func ElGamalEncryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	pStr := r.FormValue("p")
	gStr := r.FormValue("g")
	msgStr := r.FormValue("message")

	p, _ := strconv.Atoi(pStr)
	if p == 0 {
		p = 23
	}
	g, _ := strconv.Atoi(gStr)
	if g == 0 {
		g = 5
	}
	msg, _ := strconv.Atoi(msgStr)
	if msg == 0 {
		msg = 5
	}

	eg := elgamal.InitElGamal(p, g)
	eg.PrivateKey, _ = rand.Int(rand.Reader, big.NewInt(int64(p)))
	eg.PublicKey = new(big.Int).Exp(big.NewInt(int64(g)), eg.PrivateKey, big.NewInt(int64(p)))

	c1_1, c2_1 := eg.EncryptNumber(msg)
	c1_2, c2_2 := eg.EncryptNumber(msg)

	data := PageData{
		Title:         "TP 3: Asymmetric & MitM Lab",
		ActiveTab:     "tp3",
		ActiveSubTab:  "elgamal",
		ElGamalResult: &ElGamalEncryptResult{
			p:    strconv.Itoa(p),
			g:    strconv.Itoa(g),
			C1_1: c1_1,
			C2_1: c2_1,
			C1_2: c1_2,
			C2_2: c2_2,
		},
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

// ElGamal Forgery (Malleability)
func ElGamalForgeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	c1Str := r.FormValue("c1")
	c2Str := r.FormValue("c2")
	multStr := r.FormValue("multiplier")

	c1, _ := new(big.Int).SetString(c1Str, 10)
	c2, _ := new(big.Int).SetString(c2Str, 10)
	mult, _ := new(big.Int).SetString(multStr, 10)

	if c1 == nil || c2 == nil {
		c1 = big.NewInt(10)
		c2 = big.NewInt(15)
		mult = big.NewInt(2)
	}

	p := new(big.Int).Add(c2, big.NewInt(100))

	for i := int64(2); i < 1000; i++ {
		testP := big.NewInt(i)
		if testP.ProbablyPrime(10) {
			p = testP
			break
		}
	}

	c2Mult := new(big.Int).Mul(c2, mult)
	c2Mult.Mod(c2Mult, p)

	originalMsg := new(big.Int).Mod(c2, p)
	forsMsg := new(big.Int).Mod(c2Mult, p)

	data := PageData{
		Title:         "TP 3: Asymmetric & MitM Lab",
		ActiveTab:     "tp3",
		ActiveSubTab:  "elgamal",
		ElGamalForge: &ElGamalForgeResult{
			OriginalMsg: originalMsg.String(),
			ForgedMsg:   forsMsg.String(),
		},
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

// ECC Point Operations
func ECCPointHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	pxStr := r.FormValue("px")
	pyStr := r.FormValue("py")
	kStr := r.FormValue("k")

	px, _ := strconv.Atoi(pxStr)
	py, _ := strconv.Atoi(pyStr)
	k, _ := strconv.Atoi(kStr)

	if px == 0 {
		px = 5
	}
	if py == 0 {
		py = 12
	}
	if k == 0 {
		k = 3
	}

	result := calculateECCMult(px, py, k)

	data := PageData{
		Title:         "TP 3: Asymmetric & MitM Lab",
		ActiveTab:     "tp3",
		ActiveSubTab:  "ecc",
		ECCResult:     result,
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

func calculateECCMult(px, py, k int) *ECCResult {
	p := 97
	a := 0
	b := 7

	logs := []string{}

	x, y := px, py
	for i := 1; i < k; i++ {
		logs = append(logs, fmt.Sprintf("Step %d: Adding point (%d,%d)", i+1, x, y))
		x, y = pointAdd(x, y, px, py, p, a, b)
		logs = append(logs, fmt.Sprintf("  -> Result: (%d,%d)", x, y))
	}

	return &ECCResult{
		Qx:   strconv.Itoa(x),
		Qy:   strconv.Itoa(y),
		Logs: logs,
	}
}

func pointAdd(x1, y1, x2, y2, p, a, b int) (int, int) {
	if x1 == x2 && y1 == y2 {
		lambda := (3*x1*x1 + a) * modInverse(2*y1, p) % p
		x3 := (lambda*lambda - 2*x1) % p
		y3 := (lambda*(x1-x3) - y1) % p
		return modPos(x3, p), modPos(y3, p)
	}

	lambda := (y2 - y1) * modInverse(x2-x1, p) % p
	x3 := (lambda*lambda - x1 - x2) % p
	y3 := (lambda*(x1-x3) - y1) % p
	return modPos(x3, p), modPos(y3, p)
}

func modInverse(a, m int) int {
	a = modPos(a, m)
	for i := 1; i < m; i++ {
		if (a*i)%m == 1 {
			return i
		}
	}
	return 1
}

func modPos(n, p int) int {
	result := n % p
	if result < 0 {
		result += p
	}
	return result
}

// ECDH Key Exchange
func ECDHHandler(w http.ResponseWriter, r *http.Request) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}
	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	sharedX, sharedY := elliptic.P256().ScalarMult(bobPriv.PublicKey.X, bobPriv.PublicKey.Y, alicePriv.D.Bytes())

	sharedSecret := sha256.Sum256(append(sharedX.Bytes(), sharedY.Bytes()...))

	data := PageData{
		Title:         "TP 3: Asymmetric & MitM Lab",
		ActiveTab:     "tp3",
		ActiveSubTab:  "ecc",
		ECDHResult: &ECDHResult{
			AlicePrivate: alicePriv.D.String(),
			AlicePublicX: alicePriv.PublicKey.X.String(),
			AlicePublicY: alicePriv.PublicKey.Y.String(),
			BobPrivate:   bobPriv.D.String(),
			BobPublicX:   bobPriv.PublicKey.X.String(),
			BobPublicY:   bobPriv.PublicKey.Y.String(),
			SharedSecret: sharedX.String(),
		},
		ECDHAESKey: hex.EncodeToString(sharedSecret[:]),
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

// --- TP 4 Handlers ---

func TP4Handler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:     "TP 4: Integrity & Signatures Lab",
		ActiveTab: "tp4",
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func HashHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp4", http.StatusSeeOther)
		return
	}

	inputText := r.FormValue("input_text")
	if inputText == "" {
		inputText = "Hello World"
	}

	hashes := make(map[string]string)

	hMD5 := md5.Sum([]byte(inputText))
	hashes["MD5"] = fmt.Sprintf("%x", hMD5)

	h256 := sha256.Sum256([]byte(inputText))
	hashes["SHA-256"] = fmt.Sprintf("%x", h256)

	h512 := sha512.Sum512([]byte(inputText))
	hashes["SHA-512"] = fmt.Sprintf("%x", h512)

	data1 := []byte(inputText)
	data2 := make([]byte, len(data1))
	copy(data2, data1)
	if len(data2) > 0 {
		data2[0] ^= 1
	}

	hA1 := sha256.Sum256(data1)
	hA2 := sha256.Sum256(data2)
	avalanche := analyzer.CalculateAvalanche(hA1[:], hA2[:])

	data := PageData{
		Title:     "TP 4: Integrity & Signatures Lab",
		ActiveTab: "tp4",
		InputText: inputText,
		Hashes:    hashes,
		HashAval:  avalanche,
	}

	templates.ExecuteTemplate(w, "base.html", data)
}

// --- TP 6 Handlers ---

func TP6Handler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:     "TP 6: Secure Application Lab",
		ActiveTab: "tp6",
		ChatLog:   chatLog,
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func createBMPHeader(width, height int) []byte {
	rowSize := width
	pixelDataSize := rowSize * height
	headerSize := 54

	header := make([]byte, headerSize)

	header[0] = 'B'
	header[1] = 'M'

	fileSize := pixelDataSize + headerSize
	header[2] = byte(fileSize)
	header[3] = byte(fileSize >> 8)
	header[4] = byte(fileSize >> 16)
	header[5] = byte(fileSize >> 24)

	header[10] = byte(headerSize)

	header[14] = 40
	header[18] = byte(width)
	header[19] = byte(width >> 8)
	header[22] = byte(height)
	header[23] = byte(height >> 8)

	header[26] = 1
	header[28] = 8

	return header
}

var chatSessionKey string

func ChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp6", http.StatusSeeOther)
		return
	}

	msg := strings.TrimSpace(r.FormValue("message"))
	if msg == "" {
		http.Redirect(w, r, "/tp6", http.StatusSeeOther)
		return
	}

	if len(chatLog) >= 50 {
		chatLog = chatLog[len(chatLog)-50:]
	}

	aesAlgo, err := internalaes.InitAES("1234567890123456")
	if err != nil {
		log.Printf("Chat AES init error: %v", err)
		http.Redirect(w, r, "/tp6", http.StatusSeeOther)
		return
	}

	paddedMsg := msg
	for len(paddedMsg)%16 != 0 {
		paddedMsg += " "
	}
	encrypted := aesAlgo.EncryptECB([]byte(paddedMsg))
	hash := sha256.Sum256(encrypted)

	if chatSessionKey == "" {
		keyBytes := make([]byte, 16)
		rand.Read(keyBytes)
		chatSessionKey = hex.EncodeToString(keyBytes)
	}

	logEntry := fmt.Sprintf("[%s] User: %s | Enc: %x... | Hash: %x...", 
		time.Now().Format("15:04:05"), msg, encrypted[:8], hash[:4])
	chatLog = append(chatLog, logEntry)

	http.Redirect(w, r, "/tp6", http.StatusSeeOther)
}

func ImageServeHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, "/tp2/img/") {
		http.NotFound(w, r)
		return
	}

	filename := strings.TrimPrefix(path, "/tp2/img/")
	filepath := os.TempDir() + "/" + filename

	http.ServeFile(w, r, filepath)
}
