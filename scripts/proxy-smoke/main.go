// proxy-smoke creates one temporary public tunnel, checks SDK startup/conflicts
// and PROXY forwarding, then deletes it. Run explicitly with go run ./scripts/proxy-smoke.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/darron/go-opentunnel"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (result error) {
	// Allow the CLI's five-minute provisioning window plus time for forwarding.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	client, err := opentunnel.NewClient(opentunnel.ClientOptions{Storage: opentunnel.NewMemoryStorage()})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	// Independent cleanup context still runs after an interrupted/failed provision.
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		var id, token string
		if identity, err := client.Get(clean, "proxy-smoke"); err == nil && identity != nil {
			id, token = identity.ID, identity.Token
		}
		if id == "" {
			if pending, err := client.Pending(clean, "proxy-smoke"); err == nil && pending != nil {
				id, token = pending.ID, pending.Token
			}
		}
		if err := client.Remove(clean, "proxy-smoke"); err != nil {
			result = errors.Join(result, err)
			return
		}
		if id != "" {
			_, err := client.API().Get(clean, id, token)
			var apiErr *opentunnel.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 {
				result = errors.Join(result, errors.New("remote deletion not confirmed by API 404"))
				return
			}
		}
		fmt.Println("PASS: temporary identity removed; remote API 404 confirmed")
	}()
	provisionCtx, provisionCancel := context.WithTimeout(ctx, 5*time.Minute)
	var stages []opentunnel.ProvisionStage
	identity, err := client.EnsureWithOptions(provisionCtx, "proxy-smoke", opentunnel.ProvisionOptions{OnProgress: func(s opentunnel.ProvisionStage) { stages = append(stages, s) }})
	provisionCancel()
	if err != nil {
		return err
	}
	if len(stages) == 0 || stages[len(stages)-1] != opentunnel.StageReady {
		return errors.New("provisioning progress did not report ready")
	}
	stages = nil
	_, err = client.EnsureWithOptions(ctx, "proxy-smoke", opentunnel.ProvisionOptions{OnProgress: func(s opentunnel.ProvisionStage) { stages = append(stages, s) }})
	if err != nil {
		return err
	}
	if len(stages) != 2 || stages[0] != opentunnel.StageCheckingCertificate || stages[1] != opentunnel.StageReady {
		return errors.New("reused identity progress did not check certificate then report ready")
	}
	backend, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	var mode atomic.Value
	mode.Store("")
	failures := make(chan error, 8)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { _ = conn.Close() }()
				version, ok := mode.Load().(string)
				if !ok {
					failures <- errors.New("invalid smoke backend mode")
					return
				}
				if err := serve(conn, version, identity.Hostname); err != nil {
					failures <- err
				}
			}()
		}
	}()
	defer func() { _ = backend.Close(); workers.Wait() }()
	var startupObserved atomic.Bool
	connection, err := client.Connect(ctx, opentunnel.ConnectOptions{Profile: "proxy-smoke", Routes: opentunnel.Routes{"@": backend.Addr().String()}, Lifetime: ctx, OnEvent: func(e opentunnel.Event) {
		if e.Type == "connected" {
			startupObserved.Store(true)
		}
	}})
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	publicURL, err := opentunnel.PublicURL(opentunnel.RootRoute, identity.Hostname)
	if err != nil || connection.URLs()[opentunnel.RootRoute] != publicURL || !startupObserved.Load() {
		return errors.New("URL snapshot or startup observer mismatch")
	}
	// A separate Client bypasses in-process route ownership checks and exercises
	// the hosted relay's conflict response with the same temporary credentials.
	otherStore := opentunnel.NewMemoryStorage()
	if err := otherStore.Save(ctx, "proxy-smoke", *identity); err != nil {
		return err
	}
	other, err := opentunnel.NewClient(opentunnel.ClientOptions{Storage: otherStore})
	if err != nil {
		return err
	}
	defer func() { _ = other.Close() }()
	conflictCtx, stopConflict := context.WithTimeout(ctx, 30*time.Second)
	duplicate, err := other.Connect(conflictCtx, opentunnel.ConnectOptions{Profile: "proxy-smoke", Routes: opentunnel.Routes{"@": backend.Addr().String()}, OnRouteConflict: opentunnel.RouteConflictFail})
	stopConflict()
	if duplicate != nil {
		_ = duplicate.Close()
	}
	var conflict *opentunnel.AttachError
	if !errors.As(err, &conflict) || conflict.Code != "route_conflict" {
		return fmt.Errorf("expected hosted route_conflict, got %w", err)
	}
	fmt.Println("PASS: Ensure progress/reuse, URL snapshots, startup observer and hosted fatal route conflict")
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	visitor := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	for _, version := range []opentunnel.ProxyProtocol{"", opentunnel.ProxyProtocolV1, opentunnel.ProxyProtocolV2} {
		mode.Store(string(version))
		if err := connection.SetRoutesWithOptions(opentunnel.Routes{"@": backend.Addr().String()}, map[string]opentunnel.RouteOptions{"@": {ProxyProtocol: version}}); err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+identity.Hostname+"/check", nil)
		if err != nil {
			return err
		}
		response, err := visitor.Do(request)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || string(body) != "proxy-smoke-ok" {
			return errors.New("visitor response failed")
		}
		select {
		case err := <-failures:
			return err
		default:
		}
		fmt.Printf("PASS: public HTTPS forwarding mode=%q; backend preamble verified before HTTP\n", version)
	}
	return nil
}

func serve(conn net.Conn, mode, hostname string) error {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	switch mode {
	case "v1":
		header, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		fields := strings.Fields(header)
		if len(fields) != 6 || fields[0] != "PROXY" || (fields[1] != "TCP4" && fields[1] != "TCP6") || fields[5] != "443" || !strings.HasSuffix(header, "\r\n") {
			return errors.New("unexpected v1 preamble")
		}
	case "v2":
		fixed := make([]byte, 16)
		if _, err := io.ReadFull(reader, fixed); err != nil {
			return err
		}
		if !bytes.Equal(fixed[:12], []byte{13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10}) || fixed[12] != 0x21 {
			return errors.New("unexpected v2 signature/command")
		}
		size := int(binary.BigEndian.Uint16(fixed[14:]))
		if size > 294 {
			return errors.New("oversized v2 preamble")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return err
		}
		addrLen := 12
		if fixed[13] == 0x21 {
			addrLen = 36
		} else if fixed[13] != 0x11 {
			return errors.New("unexpected v2 family")
		}
		if len(payload) < addrLen+3 || binary.BigEndian.Uint16(payload[addrLen-2:addrLen]) != 443 || payload[addrLen] != 0x02 || int(binary.BigEndian.Uint16(payload[addrLen+1:addrLen+3])) != len(hostname) || string(payload[addrLen+3:]) != hostname {
			return errors.New("unexpected v2 address/authority")
		}
	}
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	_ = request.Body.Close()
	if request.Method != "GET" || request.URL.Path != "/check" {
		return errors.New("HTTP payload changed")
	}
	_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nproxy-smoke-ok")
	return err
}
