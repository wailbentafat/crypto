.PHONY: build run serve clean test

BINARY=crypto

build:
	go build -o $(BINARY) ./cmd/main.go

run: build
	./$(BINARY) $(ARGS)

serve: build
	./$(BINARY) -serve -port 8082

clean:
	rm -f $(BINARY)

test:
	go test ./...

help:
	@echo "Available targets:"
	@echo "  build    - Build the crypto binary"
	@echo "  run      - Run with optional ARGS (e.g., make run ARGS='-a caesar -m encrypt -s 3 hello')"
	@echo "  serve    - Start the web server on port 8080"
	@echo "  clean    - Remove built binary"
	@echo "  test     - Run tests"
	@echo ""
	@echo "Examples:"
	@echo "  make run ARGS='-a caesar -m encrypt -s 3 \"Hello World\"'"
	@echo "  make run ARGS='-a aes -m encrypt -k mykey \"secret message\"'"
	@echo "  make run ARGS='-a md5 \"test string\"'"