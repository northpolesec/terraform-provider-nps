default: fmt build

GPG_TTY ?= $(error "GPG_TTY should be set to your current TTY")
GITHUB_TOKEN ?= $(error "GITHUB_TOKEN must be set to a valid GitHub personal access token")

build:
	go build -v ./...

install: build
	go install -v ./...

release:
	GITHUB_TOKEN=$(GITHUB_TOKEN) GPG_TTY=$(GPG_TTY) GPG_FINGERPRINT=FAC30F80B97AF428B9DB829C4E48D0B23E8E1A00 goreleaser release --clean

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -timeout=120s -parallel=10 ./...

testacc:
	TF_ACC=1 go test -v -cover -timeout 120m ./...

.PHONY: build install release fmt test testacc
