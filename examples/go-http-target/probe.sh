#!/bin/sh
set -eu
export GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOPACKAGESDRIVER=off
export GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly GOMAXPROCS=2
export GOCACHE=/work/cache GOMODCACHE=/work/mod GOTMPDIR=/work/build HOME=/work
mkdir /work/source /work/build
cp -R /input/. /work/source/
cd /work/source
/usr/local/go/bin/go build -p 1 -o /work/server ./cmd/server
# The complete request oracle stays inside this unchanged, supplied harness.
cat > /work/probe.go <<'GO'
package main

import (
    "bufio"
    "bytes"
    "context"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "time"
)

func request(role, path string) (int, []byte) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    server := exec.CommandContext(ctx, "/work/server")
    server.Stderr = os.Stderr
    stdout, err := server.StdoutPipe()
    if err != nil { panic(err) }
    if err := server.Start(); err != nil { panic(err) }
    defer func() { server.Process.Kill(); server.Wait() }()
    logs := bufio.NewScanner(stdout)
    logs.Split(func(data []byte, atEOF bool) (int, []byte, error) {
        if end := bytes.IndexByte(data, '\n'); end >= 0 { return end+1, data[:end+1], nil }
        if atEOF && len(data) > 0 { return len(data), data, nil }
        return 0, nil, nil
    })
    if !logs.Scan() || !strings.HasPrefix(logs.Text(), "LISTEN 127.0.0.1:") {
        panic("server did not bind loopback")
    }
    address := strings.TrimPrefix(strings.TrimSuffix(logs.Text(), "\n"), "LISTEN ")
    fmt.Printf("TARGET %s stdout %q\n", role, logs.Text())
    request, err := http.NewRequest("GET", "http://"+address+path, nil)
    if err != nil { panic(err) }
    request.Header.Set("X-Role", role)
    client := &http.Client{Timeout: 3*time.Second, Transport: &http.Transport{Proxy: nil},
        CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
    response, err := client.Do(request)
    if err != nil { panic(err) }
    body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
    response.Body.Close()
    if err != nil || len(body) > 4096 { panic("invalid response body") }
    server.Process.Kill()
    for logs.Scan() { fmt.Printf("TARGET %s stdout %q\n", role, logs.Text()) }
    if err := logs.Err(); err != nil { panic(err) }
    fmt.Printf("HTTP %s status %d\n", role, response.StatusCode)
    fmt.Printf("HTTP %s body %q\n", role, body)
    return response.StatusCode, body
}

func main() {
    path := "/private"
    if len(os.Args) > 1 { path = os.Args[1] }
    status, body := request("guest", path)
    controlStatus, controlBody := request("admin", path)
    if controlStatus != 200 || string(controlBody) != "DATA private-record\n" {
        fmt.Println("CONTROL admin failed")
        fmt.Println("CHECK complete")
        return
    }
    fmt.Println("CONTROL admin passed")
    switch {
    case status == 200 && string(body) == "DATA private-record\n":
        fmt.Println("ORACLE unauthorized-read")
    case status == 403 && string(body) == "DENIED\n":
        fmt.Println("ORACLE access-denied")
    default:
        fmt.Println("ORACLE unknown-response")
    }
    fmt.Println("CHECK complete")
}
GO
/usr/local/go/bin/go build -p 1 -o /work/probe /work/probe.go
exec /work/probe "$@"
