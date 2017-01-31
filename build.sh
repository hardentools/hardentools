#!/bin/bash

# go get github.com/lxc/win
# go get github.com/lxc/walk
# go get github.com/akavel/rsrc
# go get golang.org/x/sys/windows/registry

$GOPATH/bin/rsrc -manifest harden.manifest -o rsrc.syso
GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc CGO_ENABLED=1 go build --ldflags '-s -w -extldflags "-static" -H windowsgui' -o Hardentools.exe
