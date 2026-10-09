.PHONY: build check test race vet lint fuzz

build:
	mkdir -p bin
	go build -o bin/otgo ./cmd/otgo
	go build -o bin/webapp ./examples/webapp

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint fmt --diff
	golangci-lint run ./...

fuzz:
	go test -run '^$$' -fuzz '^FuzzDecodeFrame$$' -fuzztime=5s .
	go test -run '^$$' -fuzz '^FuzzDecodeControl$$' -fuzztime=5s .
	go test -run '^$$' -fuzz '^FuzzRouteForSNI$$' -fuzztime=5s .

check: test vet lint build
