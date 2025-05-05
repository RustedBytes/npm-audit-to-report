default: build

fmt:
    betteralign -apply ./...
    gofumpt -l -w .

lint:
    golangci-lint run -c .golangci.yml ./...
    deadcode ./...

build: clean lint
    GOOS=linux GOARCH=amd64 go build -o npm-audit-to-report -ldflags="-s -w" main.go

clean:
    rm -f ./npm-audit-to-report
    rm -rf ./dist

release:
    goreleaser build --clean --timeout 60m
