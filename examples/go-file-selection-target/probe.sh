#!/bin/sh
set -eu
export GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOPACKAGESDRIVER=off
export GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly GOMAXPROCS=2
export GOCACHE=/work/cache GOMODCACHE=/work/mod GOTMPDIR=/work/build HOME=/work
mkdir /work/source /work/build
cp -R /input/. /work/source/
cd /work/source
/usr/local/go/bin/go build -p 1 -o /work/server ./cmd/server
cat > /work/probe.go <<'GO'
package main

import (
    "bufio"
    "context"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "time"
)

func request(label, path string) (int, string) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    server := exec.CommandContext(ctx, "/work/server")
    server.Stderr = os.Stderr
    stdout, err := server.StdoutPipe()
    if err != nil { panic(err) }
    if err := server.Start(); err != nil { panic(err) }
    defer func() { server.Process.Kill(); server.Wait() }()
    logs := bufio.NewScanner(stdout)
    if !logs.Scan() || !strings.HasPrefix(logs.Text(), "LISTEN 127.0.0.1:") {
        panic("server did not bind loopback")
    }
    address := strings.TrimPrefix(logs.Text(), "LISTEN ")
    client := &http.Client{Timeout: 3*time.Second, Transport: &http.Transport{Proxy: nil},
        CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
    response, err := client.Get("http://" + address + path)
    if err != nil { panic(err) }
    body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
    response.Body.Close()
    if err != nil || len(body) > 4096 { panic("invalid response body") }
    server.Process.Kill()
    for logs.Scan() { fmt.Printf("TARGET %s stdout %q\n", label, logs.Text()) }
    if err := logs.Err(); err != nil { panic(err) }
    fmt.Printf("HTTP %s status %d body %q\n", label, response.StatusCode, body)
    return response.StatusCode, string(body)
}

func main() {
    status, body := request("private", "/download?asset=private.txt")
    publicStatus, publicBody := request("public", "/download?asset=public.txt")
    noticeStatus, noticeBody := request("notice", "/notice?asset=private.txt")
    if publicStatus != 200 || publicBody != "DATA public-record\n" ||
        noticeStatus != 200 || noticeBody != "DATA public-notice\n" {
        fmt.Println("CONTROL failed")
        fmt.Println("ORACLE unknown-response")
        fmt.Println("CHECK complete")
        return
    }
    fmt.Println("CONTROL passed")
    switch {
    case status == 200 && body == "DATA private-record\n":
        fmt.Println("ORACLE unauthorized-read")
    case status == 404 && body == "unavailable\n":
        fmt.Println("ORACLE private-blocked")
    default:
        fmt.Println("ORACLE unknown-response")
    }
    fmt.Println("CHECK complete")
}
GO
/usr/local/go/bin/go build -p 1 -o /work/probe /work/probe.go
exec /work/probe
