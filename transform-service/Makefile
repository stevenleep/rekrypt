.PHONY: all build run dev clean

BINARY=rekrypt-transform
PORT=8080

all: build

build:
	@echo "Building transform service..."
	CGO_ENABLED=1 go build -o $(BINARY)

run: build
	./$(BINARY) -port $(PORT)

dev:
	CGO_ENABLED=1 go run main.go

clean:
	rm -f $(BINARY)
