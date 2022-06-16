.DEFAULT_GOAL := build
BUILD_FOLDER  = $(shell pwd)/build
FLAGS_WINDOWS = GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc CGO_ENABLED=1
MINGW32GCC    = $(shell command -v i686-w64-mingw32-gcc 2> /dev/null)
GOFLAGS_WINUI = -trimpath -buildvcs=false --ldflags '-s -w -extldflags "-static" -H windowsgui'
GOFLAGS_CLI   = -trimpath -buildvcs=false -tags=cli --ldflags '-s -w -extldflags "-static"'

clean:
	rm -rf $(BUILD_FOLDER)

pre: clean
	@mkdir -p $(BUILD_FOLDER)
	cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % go install %
	go mod download

build: pre lint vet
ifndef MINGW32GCC
	$(error "i686-w64-mingw32-gcc is not available. Please install package mingw32-cross-gcc")
endif

	@echo "[builder] Building Windows executable"
	@mkdir -p $(BUILD_FOLDER)/
	$(GOPATH)/bin/rsrc -arch 386 -manifest harden.manifest -ico harden.ico -o rsrc.syso
	$(FLAGS_WINDOWS) go build $(GOFLAGS_WINUI) -o $(BUILD_FOLDER)/hardentools.exe
	$(FLAGS_WINDOWS) cyclonedx-gomod app -output hardentools.bom.xml -licenses
	@echo "[builder] Building Windows commandline executable"
	$(FLAGS_WINDOWS) go build $(GOFLAGS_CLI) -o $(BUILD_FOLDER)/hardentools-cli.exe
	$(FLAGS_WINDOWS) GOFLAGS=-tags=cli cyclonedx-gomod app -output hardentools-cli.bom.xml -licenses
	@echo "[builder] Done!"


lint: fmt
	@echo "[lint] Running linter on codebase"
	@golint ./...

fmt:
	@echo "[gofmt] Formatting code"
	gofmt -s -w .

vet: fmt
	@echo "[go vet] Checking code"
	$(FLAGS_WINDOWS) go vet ./...

