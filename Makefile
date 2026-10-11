.PHONY: build build-example check test race vet lint fuzz

# Go records VCS metadata in checkout builds. Archives can supply it explicitly.
BUILD_REVISION ?=
BUILD_STATE ?= unknown
OTGO_BUILD_FLAGS =
ifneq ($(strip $(BUILD_REVISION)),)
OTGO_BUILD_FLAGS += -ldflags="-X main.buildRevision=$(BUILD_REVISION) -X main.buildState=$(BUILD_STATE)"
endif

build:
	mkdir -p bin
	go build $(OTGO_BUILD_FLAGS) -o bin/otgo ./cmd/otgo

build-example:
	mkdir -p bin
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
	go test -run '^$$' -fuzz '^FuzzProxyPeer$$' -fuzztime=5s .

check: test vet lint build
