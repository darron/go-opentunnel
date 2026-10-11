.PHONY: build build-example check test race vet lint fuzz fuzz-sustained

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

# CI uses this longer, bounded pass. Keep the target list explicit so the
# security coverage does not vary as unrelated fuzz tests are added.
FUZZ_TIME ?= 45s
FUZZ_PROCS ?= 2
fuzz-sustained:
	GOMAXPROCS=$(FUZZ_PROCS) go test -run '^$$' -fuzz '^FuzzDecodeFrame$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PROCS) .
	GOMAXPROCS=$(FUZZ_PROCS) go test -run '^$$' -fuzz '^FuzzDecodeControl$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PROCS) .
	GOMAXPROCS=$(FUZZ_PROCS) go test -run '^$$' -fuzz '^FuzzRouteForSNI$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PROCS) .
	GOMAXPROCS=$(FUZZ_PROCS) go test -run '^$$' -fuzz '^FuzzProxyPeer$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PROCS) .
	GOMAXPROCS=$(FUZZ_PROCS) go test -run '^$$' -fuzz '^FuzzAnonymousBoundary$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PROCS) ./internal/authproxy

check: test vet lint build
