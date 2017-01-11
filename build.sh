#!/bin/bash

GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc CGO_ENABLED=1 go build --ldflags '-s -w -extldflags "-static"' -o Hardentools.exe
