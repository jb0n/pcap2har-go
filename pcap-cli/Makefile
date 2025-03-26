VERSION  := $(shell git describe --tags 2>/dev/null || git rev-parse --short HEAD)
all: decode-example

decode-example: cmd/decode-example/main.go general/*.go example/*.go go.*
	go build -o decode-example -ldflags "-X github.com/jb0n/pcap2har-go/pcap-cli/cli.Version=$(VERSION)" cmd/decode-example/*.go

test:
	go test ./...

lint:
	golangci-lint run
	./ensure-gofmt.sh
