# CryptoLab - Makefile

.PHONY: all build run serve serve-bg clean test help

# Variables
BINARY_NAME=crypto
PORT=8080

# Build le projet
build:
	go build -o $(BINARY_NAME) ./cmd/...

# Lancer le serveur web (UI)
serve: build
	./$(BINARY_NAME) -serve -port $(PORT)

# Lancer en arrière-plan
serve-bg: build
	nohup ./$(BINARY_NAME) -serve -port $(PORT) > server.log 2>&1 &
	@echo "Server started at http://localhost:$(PORT)"
	@echo "Pour arrêter: pkill -f './crypto'"

# Commandes CLI - Chiffrement César
run-caesar:
	./$(BINARY_NAME) -a caesar -s 3 -m encrypt "HELLO"

# Commandes CLI - AES
run-aes:
	./$(BINARY_NAME) -a aes -k "0123456789ABCDEF" -m encrypt "Message"

# Commandes CLI - MD5
run-md5:
	./$(BINARY_NAME) -a md5 "test message"

# Commandes CLI - SHA-256
run-sha256:
	./$(BINARY_NAME) -a sha256 "message"

# Commandes CLI - SHA-512
run-sha512:
	./$(BINARY_NAME) -a sha512 "message"

# Commandes CLI - Générer clés RSA
run-rsa:
	./$(BINARY_NAME) -a rsa -m keygen -bits 2048

# Commandes CLI - Générer clés RSA 1024
run-rsa-1024:
	./$(BINARY_NAME) -a rsa -m keygen -bits 1024

# Commandes CLI - DES
run-des:
	./$(BINARY_NAME) -a des -k "my8charkey" -m encrypt "Message"

# Commandes CLI - Vigenere
run-vigenere:
	./$(BINARY_NAME) -a vigenere -k "KEY" -m encrypt "HELLO"

# Commandes CLI - Hill
run-hill:
	./$(BINARY_NAME) -a hill -k "GYBNQKURP" -m encrypt "HELLO"

# Commandes CLI - RC4
run-rc4:
	./$(BINARY_NAME) -a rc4 -k "secret" -m encrypt "Message"

# Commandes CLI - RC6
run-rc6:
	./$(BINARY_NAME) -a rc6 -k "secretkey12345678" -m encrypt "Message"

# Commandes CLI - Serpent
run-serpent:
	./$(BINARY_NAME) -a serpent -k "secretkey12345678" -m encrypt "Message"

# WebSocket Chat
serve-ws: build
	@echo "========================================"
	@echo "WebSocket Chat Server started!"
	@echo "========================================"
	@echo "1. Open: http://localhost:8080/cmd/websocket_test.html"
	@echo "2. Or open http://localhost:8080/tp6"
	@echo "3. Pour tester avec 2 utilisateurs:"
	@echo "   - Ouvrez websocket_test.html dans 2 onglets"
	@echo "   - Utilisez le meme nom de salle"
	@echo ""
	./$(BINARY_NAME) -serve -port 8080

# Nettoyer les fichiers
clean:
	rm -f $(BINARY_NAME) server.log nohup.out

# Tests
test:
	go test ./...

# Aide
help:
	@echo "CryptoLab - Commandes disponibles:"
	@echo "========================================"
	@echo "  make serve          - Lancer le serveur web (http://localhost:8080)"
	@echo "  make serve-bg       - Lancer en arrière-plan"
	@echo ""
	@echo "Commandes CLI - Chiffrement Classique:"
	@echo "  make run-caesar     - Tester César"
	@echo "  make run-vigenere   - Tester Vigenere"
	@echo "  make run-hill       - Tester Hill"
	@echo ""
	@echo "Commandes CLI - Chiffrement Moderne:"
	@echo "  make run-aes        - Tester AES"
	@echo "  make run-des        - Tester DES"
	@echo "  make run-rc4        - Tester RC4"
	@echo "  make run-rc6        - Tester RC6"
	@echo "  make run-serpent    - Tester Serpent"
	@echo ""
	@echo "Commandes CLI - Fonctions de Hachage:"
	@echo "  make run-md5        - Tester MD5"
	@echo "  make run-sha256     - Tester SHA-256"
	@echo "  make run-sha512     - Tester SHA-512"
	@echo ""
	@echo "Commandes CLI - Cryptographie Asymétrique:"
	@echo "  make run-rsa        - Générer clés RSA 2048 bits"
	@echo "  make run-rsa-1024   - Générer clés RSA 1024 bits"
	@echo ""
	@echo "Autres:"
	@echo "  make build          - Compiler le projet"
	@echo "  make test           - Lancer les tests"
	@echo "  make clean          - Nettoyer les fichiers"