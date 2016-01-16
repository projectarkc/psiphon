package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"bitbucket.org/psiphon/psiphon-circumvention-system/go/utils/crypto"
	tlsdialer "gopkg.in/getlantern/tlsdialer.v1"
)

import "git.torproject.org/pluggable-transports/goptlib.git"

const (
	// The size of the largest chunk of data we will read from the SOCKS
	// port before forwarding it in a request, and the maximum size of a
	// body we are willing to handle in a reply.
	maxPayloadLength = 0x10000
	// We must poll the server to see if it has anything to send; there is
	// no way for the server to push data back to us until we send an HTTP
	// request. When a timer expires, we send a request even if it has an
	// empty body. The interval starts at this value and then grows.
	initPollInterval = 100 * time.Millisecond
	// Maximum polling interval.
	maxPollInterval = 5 * time.Second
	// Geometric increase in the polling interval each time we fail to read
	// data.
	pollIntervalMultiplier = 1.5

	methodName = "meek"
)

// RequestInfo encapsulates all the configuration used for a request–response
// roundtrip, including variables that may come from SOCKS args or from the
// command line.
type RequestInfo struct {
	MeekProtocolVersion   int
	ClientPublicKeyBase64 string
	ObfuscatedKeyword     string
	PsiphonServerAddr     string
	SshSessionID          string
	PayloadCookie         *http.Cookie
	RequestURL            string
	HttpTransport         *http.Transport
}

type Cookie struct {
	PsiphonServerAddr   string `json:"p"`
	SshSessionID        string `json:"s"`
	MeekProtocolVersion int    `json:"v"`
}

func DialTLS(tlsaddr string) func(string, string) (net.Conn, error) {
	//Credits: Ox Cart of the Lantern project
	//https://gist.github.com/oxtoacart/5e78d25a7f9a9cda10cd
	//https://github.com/getlantern/tlsdialer/tree/v1
	return func(n, addr string) (net.Conn, error) {
		return tlsdialer.Dial("tcp", tlsaddr, false, nil)
	}
}

func randInt(min int, max int) int {
	rand.Seed(time.Now().UTC().UnixNano())
	return min + rand.Intn(max-min)
}

// Do an HTTP roundtrip using the payload data in buf and the request metadata
// in info.
func roundTrip(buf []byte, info *RequestInfo) (response *http.Response, err error) {
	req, err := http.NewRequest("POST", info.RequestURL, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	// Don't use the default user agent ("Go 1.1 package http").
	// For now, just omit the header (net/http/request.go: "may be blank to not send the header").
	req.Header.Set("User-Agent", "")

	req.AddCookie(info.PayloadCookie)

	// Retry loop, which assumes entire request failed (underlying
	// transport protocol such as SSH will fail if extra bytes are
	// replayed in either direction due to partial request success
	// followed by retry).
	// This retry mitigates intermittent failures between the client
	// and front/server.
	for i := 0; i <= 1; i++ {
		response, err = info.HttpTransport.RoundTrip(req)
		if err == nil {
			return
		}
		log.Printf("RoundTrip error: %s", err)
	}
	return
}

// Send the data in buf to the remote URL, wait for a reply, and feed the reply
// body back into conn.
func sendRecv(buf []byte, conn net.Conn, info *RequestInfo) (int64, error) {
	resp, err := roundTrip(buf, info)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New(fmt.Sprintf("status code was %d, not %d", resp.StatusCode, http.StatusOK))
	}

	// watch response cookies for meek session key token.
	// Once found it must be used for all consecutive requests made to the server
	for _, c := range resp.Cookies() {
		if info.PayloadCookie.Name == c.Name {
			info.PayloadCookie.Value = c.Value
			break
		}
	}

	return io.Copy(conn, resp.Body)
}

func makeCookie(info *RequestInfo) (*http.Cookie, error) {
	var clientPublicKey, dummyKey [32]byte

	keydata, err := base64.StdEncoding.DecodeString(info.ClientPublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding info.ClientPublicKeyBase64: %s", err)
	}

	copy(clientPublicKey[:], keydata)
	cr := crypto.New(clientPublicKey, dummyKey)

	cookie := &Cookie{
		PsiphonServerAddr:   info.PsiphonServerAddr,
		SshSessionID:        info.SshSessionID,
		MeekProtocolVersion: info.MeekProtocolVersion,
	}

	j, err := json.Marshal(cookie)
	if err != nil {
		return nil, err
	}
	encrypted, err := cr.Encrypt(j)
	if err != nil {
		return nil, err
	}
	obfuscated, err := cr.Obfuscate(encrypted, info.ObfuscatedKeyword)
	if err != nil {
		return nil, err
	}
	cookieValue := base64.StdEncoding.EncodeToString(obfuscated)
	cookieName := string(byte(randInt(65, 90)))
	return &http.Cookie{Name: cookieName, Value: cookieValue}, nil
}

// Callback for new SOCKS requests.
func handler(conn *pt.SocksConn) error {
	defer conn.Close()
	err := conn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		return err
	}

	var frontingHostname, targetAddr string

	targetAddr = conn.Req.Target
	frontingHostname, _ = conn.Req.Args.Get("fhostname")

	var info RequestInfo

	info.ClientPublicKeyBase64, _ = conn.Req.Args.Get("cpubkey")
	info.PsiphonServerAddr, _ = conn.Req.Args.Get("pserver")
	info.SshSessionID, _ = conn.Req.Args.Get("sshid")
	info.ObfuscatedKeyword, _ = conn.Req.Args.Get("obfskey")

	//Indicates that the client understands chunked responses of arbitrary length
	//info.MeekProtocolVersion = 1

	//protocol v.2 indicates that client handles Set-Cookie header in the response
	info.MeekProtocolVersion = 2

	if targetAddr == "" {
		return errors.New("target address is missing from SOCKS request")
	}

	if info.ClientPublicKeyBase64 == "" {
		return errors.New("ClientPublicKeyBase64 is missing from SOCKS payload")
	}
	if info.PsiphonServerAddr == "" {
		return errors.New("PsiphonServerAddr is missing from SOCKS payload")
	}

	if info.SshSessionID == "" {
		return errors.New("SshSessionID is missing from SOCKS payload")
	}

	info.PayloadCookie, err = makeCookie(&info)

	if err != nil {
		return errors.New(fmt.Sprintf("Couldn't create encrypted payload: %s", err.Error()))
	}

	info.HttpTransport = &http.Transport{}

	if frontingHostname != "" {
		//set HTTP request URL to http://<frontingHostname>/
		//and use custom dialer in HTTP Transport to establish
		//TLS connection to the targetAddr

		info.RequestURL = (&url.URL{
			Scheme: "http",
			Host:   frontingHostname,
			Path:   "/",
		}).String()

		info.HttpTransport.Dial = DialTLS(targetAddr)
	} else {
		//unfronted connection
		//set HTTP request URL to http://<targetAddr>/
		//and use default HTTP Transport
		//for the RoundTrip

		info.RequestURL = (&url.URL{
			Scheme: "http",
			Host:   targetAddr,
			Path:   "/",
		}).String()
	}

	return copyLoop(conn, &info)
}

func acceptLoop(ln *pt.SocksListener) error {
	defer ln.Close()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			log.Printf("error in AcceptSocks: %s", err)
			if e, ok := err.(net.Error); ok && e.Temporary() {
				// This is a temporary error, so we can keep using this listener
				continue
			}
			return err
		}
		go func() {
			err := handler(conn)
			if err != nil {
				log.Printf("error in handling request: %s", err)
			}
		}()
	}
	return nil
}

func main() {
	var err error

	ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
	if err != nil {
		pt.CmethodError(methodName, err.Error())
		return
	}
	pt.Cmethod(methodName, ln.Version(), ln.Addr())
	acceptLoop(ln)
}
