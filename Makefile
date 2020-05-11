.PHONY: clean

build: $(find . -name '*.go' -type f)
	GOROOT=/usr/local/Cellar/go/1.13.4/libexec \
	GOPATH=${HOME}/go \
	/usr/local/Cellar/go/1.13.4/libexec/bin/go build -o bin/cm-cert-check -gcflags "all=-N -l" cm-cert-check

bin: bin
	mkdir "bin"

clean:
	rm -rf bin
