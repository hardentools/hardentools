#!/bin/bash

# go get github.com/lxn/win
# go get github.com/lxn/walk
# go get github.com/akavel/rsrc
# go get golang.org/x/sys/windows/registry

# check go version
GO_VERSION="$(go version)"
GO_VERSION="$(echo $GO_VERSION | awk '{print $3}')"
if [[ $GO_VERSION = "go1.8" ]]; then
  $GOPATH/bin/rsrc -manifest harden.manifest -ico harden.ico -o rsrc.syso
  GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc CGO_ENABLED=1 go build --ldflags '-s -w -extldflags "-static" -H windowsgui' -o hardentools.exe
else
  echo "Error: Build currently only works with go1.8"
fi
