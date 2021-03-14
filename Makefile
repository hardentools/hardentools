.DEFAULT_GOAL := build
BUILD_FOLDER   = $(shell pwd)/build
FLAGS_WINDOWS  = GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc CGO_ENABLED=1
MINGW32GCC    := $(shell command -v i686-w64-mingw32-gcc 2> /dev/null)

clean:
	rm -rf $(BUILD_FOLDER)

pre: clean
	@mkdir -p $(BUILD_FOLDER)
	env go get -d ./
	env go mod download
	go get github.com/akavel/rsrc

build: pre
ifndef MINGW32GCC
	$(error "i686-w64-mingw32-gcc is not available. Please install package mingw32-cross-gcc")
endif

	@echo "[builder] Building Windows executable"
	@mkdir -p $(BUILD_FOLDER)/
	$(GOPATH)/bin/rsrc -arch 386 -manifest harden.manifest -ico harden.ico -o rsrc.syso
	$(FLAGS_WINDOWS) go build --ldflags '-s -w -extldflags "-static" -H windowsgui' -o $(BUILD_FOLDER)/hardentools.exe
	@echo "[builder] Building Windows commandline executable"
	$(FLAGS_WINDOWS) go build --ldflags '-s -w -extldflags "-static"' -o $(BUILD_FOLDER)/hardentools-cli.exe
	@echo "[builder] Done!"


lint:
	@echo "[lint] Running linter on codebase"
	@golint ./...

fmt:
	@echo "[gofmt] Formatting code"
	gofmt -s -w .
