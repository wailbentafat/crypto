package web

import (
	"crypto/internal/AES"
	"crypto/internal/Caesar"
	"crypto/internal/Hill"
	"crypto/internal/OTP"
	"crypto/internal/Vigenere"
	"crypto/internal/analyzer"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
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
)

// PageData represents the data passed to templates.
type PageData struct {
	Title         string
	ActiveTab     string
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
	DHResult   map[string]string
	MitMActive bool
	HybridStep int
	// TP4
	Hashes   map[string]string
	HashAval float64
	// TP6
	ChatLog []string
	VoteRes map[string]int
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

		aesAlgo, _ := aes.InitAES("mysecretkey12345")

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

	aesAlgo, _ := aes.InitAES(key)
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

	aesAlgo, _ := aes.InitAES("1234567890123456")
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
		Title:     "TP 3: Asymmetric & MitM Lab",
		ActiveTab: "tp3",
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func DHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp3", http.StatusSeeOther)
		return
	}

	pStr := r.FormValue("p")
	gStr := r.FormValue("g")
	mitm := r.FormValue("mitm") == "on"

	p, _ := new(big.Int).SetString(pStr, 10)
	g, _ := new(big.Int).SetString(gStr, 10)

	if p == nil || g == nil {
		p = big.NewInt(23)
		g = big.NewInt(5)
	}

	a, _ := rand.Int(rand.Reader, p)
	A := new(big.Int).Exp(g, a, p)

	b, _ := rand.Int(rand.Reader, p)
	B := new(big.Int).Exp(g, b, p)

	res := make(map[string]string)
	res["p"] = p.String()
	res["g"] = g.String()
	res["a"] = a.String()
	res["A"] = A.String()
	res["b"] = b.String()
	res["B"] = B.String()

	if mitm {
		m, _ := rand.Int(rand.Reader, p)
		M := new(big.Int).Exp(g, m, p)
		res["m"] = m.String()
		res["M"] = M.String()
		s_am := new(big.Int).Exp(M, a, p)
		s_bm := new(big.Int).Exp(M, b, p)
		res["s_alice"] = s_am.String()
		res["s_bob"] = s_bm.String()
		res["s_mallory_alice"] = new(big.Int).Exp(A, m, p).String()
		res["s_mallory_bob"] = new(big.Int).Exp(B, m, p).String()
	} else {
		s_ab := new(big.Int).Exp(B, a, p)
		s_ba := new(big.Int).Exp(A, b, p)
		res["s_alice"] = s_ab.String()
		res["s_bob"] = s_ba.String()
	}

	data := PageData{
		Title:      "TP 3: Asymmetric & MitM Lab",
		ActiveTab:  "tp3",
		DHResult:   res,
		MitMActive: mitm,
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

func ChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tp6", http.StatusSeeOther)
		return
	}

	msg := r.FormValue("message")
	if msg != "" {
		aesAlgo, _ := aes.InitAES("1234567890123456")
		paddedMsg := msg
		for len(paddedMsg)%16 != 0 {
			paddedMsg += " "
		}
		encrypted := aesAlgo.EncryptECB([]byte(paddedMsg))
		hash := sha256.Sum256(encrypted)
		logEntry := fmt.Sprintf("User: %s | Enc: %x... | Hash: %x...", msg, encrypted[:8], hash[:4])
		chatLog = append(chatLog, logEntry)
	}

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
