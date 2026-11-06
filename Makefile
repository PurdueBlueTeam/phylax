GO      ?= go
BIN     := bin/phylax
GOOS    ?= linux
GOARCH  ?= amd64
CGO     ?= 0

.PHONY: build build-windows test race vet size gate conformance clean

build:
	CGO_ENABLED=$(CGO) $(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/phylax

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o bin/phylax-windows-amd64.exe ./cmd/phylax

test:
	$(GO) test ./...

# -race needs cgo and gcc; the other targets stay CGO_ENABLED=0.
race:
	CGO_ENABLED=1 $(GO) test -race ./...

# conformance is CI's T46 gate: the suite's own checks over the whole module
# package tree, then every module's conformance test. It runs the full 60 s
# link-loss window (no -short) and needs cgo for the race detector.
conformance:
	CGO_ENABLED=1 $(GO) test -race -count=1 ./internal/module/...
	CGO_ENABLED=1 $(GO) test -race -count=1 -run Conformance ./...

vet:
	$(GO) vet ./...
	GOOS=windows $(GO) vet ./...

size: build
	@actual=$$(stat -c%s $(BIN)); max=41943040; \
	if [ $$actual -gt $$max ]; then echo "FAIL: binary $$actual > 40MB"; exit 1; fi; \
	gzip -c $(BIN) > /tmp/phylax.gz; zsize=$$(stat -c%s /tmp/phylax.gz); zmax=15728640; \
	if [ $$zsize -gt $$zmax ]; then echo "FAIL: compressed $$zsize > 15MB"; exit 1; fi; \
	echo "OK: binary $$actual bytes, compressed $$zsize bytes"

# gate M=MX runs that milestone's acceptance tests.
gate:
	@test -n "$(M)" || { echo "usage: make gate M=M1"; exit 2; }
	$(GO) test -tags gate -run 'TestGate_$(subst M,,'$(M))' -v ./...

clean:
	rm -rf bin
