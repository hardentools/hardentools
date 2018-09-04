BUILD_FOLDER	= $(shell pwd)/build
FLAGS_WINDOWS	= GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc CGO_ENABLED=1
MINGW32GCC      := $(shell command -v i686-w64-mingw32-gcc 2> /dev/null)

lint:
	@echo "[lint] Running linter on codebase"
	@golint ./...

deps:
	@echo "[deps] Installing dependencies..."
	go mod download
	@echo "[deps] Dependencies installed."

build:
ifndef MINGW32GCC
	$(error "i686-w64-mingw32-gcc is not available. Please install package mingw32-cross-gcc")
endif

	@echo "[builder] Building Windows executable"
	@mkdir -p $(BUILD_FOLDER)/
	$(GOPATH)/bin/rsrc -manifest harden.manifest -ico harden.ico -o rsrc.syso
	$(FLAGS_WINDOWS) go build --ldflags '-s -w -extldflags "-static" -H windowsgui' -o $(BUILD_FOLDER)/hardentools.exe
	@echo "[builder] Done!"


clean:
	rm -f rsrc.syso
	rm -rf $(BUILD_FOLDER)
