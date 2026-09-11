GOPATH := $(shell go env GOPATH)


format:
	go fmt ./...

# Runs the browser-facing wallet used for end-to-end testing. Pair it with the
# issuer and verifier screens the sample server serves at /ui.
run-webwallet:
	go run ./webwallet/cmd/webwallet

test:
	go test -cover ./... -coverprofile=cover.out

lint:
	${GOPATH}/bin/staticcheck ./...

.PHONY: format test lint run-webwallet
