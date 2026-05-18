package web

import (
	"crypto/internal/Chat"
	"fmt"
	"net/http"
)

// StartServer initializes and starts the web server.
func StartServer(port int) error {
	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/", IndexHandler)
	mux.HandleFunc("/tp1", TP1Handler)
	mux.HandleFunc("/tp1/analyze", AnalyzeHandler)
	mux.HandleFunc("/tp1/crib", CribHandler)
	mux.HandleFunc("/tp2", TP2Handler)
	mux.HandleFunc("/tp2/upload", ImageUploadHandler)
	mux.HandleFunc("/tp2/benchmark", BenchmarkHandler)
	mux.HandleFunc("/tp2/avalanche", AvalancheHandler)
	mux.HandleFunc("/tp2/img/", ImageServeHandler)
	mux.HandleFunc("/tp3", TP3Handler)
	mux.HandleFunc("/tp3/tab", TP3TabHandler)
	mux.HandleFunc("/tp3/dh", DHHandler)
	mux.HandleFunc("/tp3/dh-large", DHLargeHandler)
	mux.HandleFunc("/tp3/rsa-keygen", RSAKeyGenHandler)
	mux.HandleFunc("/tp3/hybrid-encrypt", HybridEncryptHandler)
	mux.HandleFunc("/tp3/hybrid-decrypt", HybridDecryptHandler)
	mux.HandleFunc("/tp3/rsa-encrypt-text", RSATextEncryptHandler)
	mux.HandleFunc("/tp3/rsa-decrypt-text", RSATextDecryptHandler)
	mux.HandleFunc("/tp3/benchmark", HybridBenchmarkHandler)
	mux.HandleFunc("/tp3/elgamal-encrypt", ElGamalEncryptHandler)
	mux.HandleFunc("/tp3/elgamal-forge", ElGamalForgeHandler)
	mux.HandleFunc("/tp3/ecc-point", ECCPointHandler)
	mux.HandleFunc("/tp3/ecdh", ECDHHandler)
	mux.HandleFunc("/tp4", TP4Handler)
	mux.HandleFunc("/tp4/hash", HashHandler)
	mux.HandleFunc("/tp4/signature", SignatureHandler)
	mux.HandleFunc("/tp5", TP5Handler)
	mux.HandleFunc("/tp5/signature", TP5SignatureHandler)
	mux.HandleFunc("/tp6", TP6Handler)
	mux.HandleFunc("/tp6/chat", ChatHandler)
	
	// WebSocket Chat Routes
	mux.HandleFunc("/ws/chat", chat.HandleWebSocketConnection)
	mux.HandleFunc("/ws/rooms", RoomsHandler)

	fmt.Printf("CryptoLab Dashboard starting on http://localhost:%d\n", port)
	fmt.Printf("WebSocket Chat available at: ws://localhost:%d/ws/chat?room=nom_du_salon&username=votre_nom\n", port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}

// RoomsHandler shows active chat rooms
func RoomsHandler(w http.ResponseWriter, r *http.Request) {
	rooms := chat.GetRoomsInfo()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf("%v", rooms)))
}
