@ECHO OFF

set GOOS=windows
set GOARCH=386
set CGO_ENABLED=1
set CC=i686-w64-mingw32-gcc

go get
go mod download
%GOPATH%/bin/rsrc -manifest harden.manifest -ico harden.ico -o rsrc.syso
go fmt
go build --ldflags "-s -w -extldflags '-static' -H windowsgui" -o hardentools.exe
go build -tags cli --ldflags "-s -w -extldflags '-static'" -o hardentools-cli.exe