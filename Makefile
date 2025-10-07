default: fmt install

GITHUB_TOKEN ?= $(error "GITHUB_TOKEN must be set to a valid GitHub personal access token")

build:
	go build -v ./...

install: build
	go install -v ./...

release:
	GITHUB_TOKEN=$(GITHUB_TOKEN) GPG_TTY=$(tty) goreleaser release --clean

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -timeout=120s -parallel=10 ./...

testacc:
	TF_ACC=1 go test -v -cover -timeout 120m ./...

.PHONY: fmt test testacc build install
