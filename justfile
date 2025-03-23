default: build

build: clean
    GOOS=linux GOARCH=amd64 go build -o npm-audit-to-report -ldflags="-s -w" main.go

clean:
    rm -f ./npm-audit-to-report
