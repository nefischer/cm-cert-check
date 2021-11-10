.PHONY: clean

build: bin $(find . -name '*.go' -type f)
	go build -o bin/cm-cert-check .

bin:
	mkdir -p "bin"

clean:
	rm -rf bin
