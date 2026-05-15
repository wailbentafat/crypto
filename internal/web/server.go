package web

import (
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
	mux.HandleFunc("/tp3/dh", DHHandler)
	mux.HandleFunc("/tp4", TP4Handler)
	mux.HandleFunc("/tp4/hash", HashHandler)
	mux.HandleFunc("/tp6", TP6Handler)
	mux.HandleFunc("/tp6/chat", ChatHandler)

	fmt.Printf("CryptoLab Dashboard starting on http://localhost:%d\n", port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}
