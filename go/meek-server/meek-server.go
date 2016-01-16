package main

import (
	"bitbucket.org/psiphon/psiphon-circumvention-system/go/utils/crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/fzzy/radix/redis"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const MAX_PAYLOAD_LENGTH = 0x10000
const TURN_AROUND_TIMEOUT = 20 * time.Millisecond
const EXTENDED_TURN_AROUND_TIMEOUT = 100 * time.Millisecond
const MAX_SESSION_STALENESS = 45 * time.Second
const PSI_CONN_DIAL_TIMEOUT = 100 * time.Millisecond
const TCP_KEEP_ALIVE_PERIOD = 3 * time.Minute
const HTTP_CLIENT_READ_TIMEOUT = 45 * time.Second
const HTTP_CLIENT_WRITE_TIMEOUT = 10 * time.Second

const MEEK_PROTOCOL_VERSION_1 = 1

// Protocol version 2 clients should initiate a session by sending connection information in
// encrypted cookie payload. Server will initiate the session, store it in a table and return
// session token back to client via Set-Cookie header. Client should use this token on all
// consequitive request for the rest of the session.
const MEEK_PROTOCOL_VERSION_2 = 2

const MIN_SESSION_KEY_LENGTH = 8
const MAX_SESSION_KEY_LENGTH = 20
const ALPHANUMERICAL = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Default config values from Server/psi_config.py

const DEFAULT_GEOIP_SERVICE_PORT = 6000
const DEFAULT_REDIS_DB_HOST = "127.0.0.1"
const DEFAULT_REDIS_DB_PORT = 6379
const DEFAULT_REDIS_SESSION_DB_INDEX = 0
const DEFAULT_REDIS_SESSION_EXPIRE_SECONDS = 60 * 60
const DEFAULT_REDIS_DISCOVERY_DB_INDEX = 1
const DEFAULT_REDIS_DISCOVERY_EXPIRE_SECONDS = 60 * 5

type Config struct {
	Port                                int
	ListenTLS                           bool
	CookiePrivateKeyBase64              string
	ObfuscatedKeyword                   string
	LogFilename                         string
	GeoIpServicePort                    int
	RedisDbHost                         string
	RedisDbPort                         int
	RedisSessionDbIndex                 int
	RedisSessionExpireSeconds           int
	RedisDiscoveryDbIndex               int
	RedisDiscoveryExpireSeconds         int
	ClientIpAddressStrategyValueHmacKey string
	ThrottleThresholdBytes              int64
	ThrottleSleepMilliseconds           int
	ThrottleMaxPayloadSizeMultiple      float64
	ThrottleRegions                     map[string]bool
}

type ClientSessionData struct {
	MeekProtocolVersion    int    `json:"v"`
	PsiphonClientSessionId string `json:"s"`
	PsiphonServerAddress   string `json:"p"`
}

type GeoIpData struct {
	Region string `json:"region"`
	City   string `json:"city"`
	Isp    string `json:"isp"`
}

type Session struct {
	psiConn             net.Conn
	meekProtocolVersion int
	LastSeen            time.Time
	BytesTransferred    int64
	IsThrottled         bool
	meekSessionKeySent  bool
}

func (session *Session) Touch() {
	session.LastSeen = time.Now()
}

func (session *Session) Expired() bool {
	return time.Since(session.LastSeen) > MAX_SESSION_STALENESS
}

type Dispatcher struct {
	sessionMap map[string]*Session
	lock       sync.RWMutex
	crypto     *crypto.Crypto
	config     *Config
}

func (dispatcher *Dispatcher) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	// Keeping client's cookie around because we want to re-use its name
	var clientCookie *http.Cookie
	for _, c := range request.Cookies() {
		clientCookie = c
		break
	}
	if clientCookie == nil {
		log.Println("Cookie is not present in the HTTP request")
		dispatcher.terminateConnection(responseWriter, request)
		return
	}

	if request.Method != "POST" {
		log.Printf("unexpected request type: %s", request.Method)
		dispatcher.terminateConnection(responseWriter, request)
		return
	}

	for key, value := range request.Header {
		if strings.Contains(strings.ToLower(key), "x-online-host") {
			log.Printf("X-Online-Host: %s %+v", key, value)
			dispatcher.terminateConnection(responseWriter, request)
			return
		}
	}

	sessionKey, session, err := dispatcher.GetSession(request, clientCookie.Value)
	if err != nil {
		log.Printf("GetSession: %s", err)
		dispatcher.terminateConnection(responseWriter, request)
		return
	}

	sessionCookie := &http.Cookie{Name: clientCookie.Name, Value: sessionKey}

	err = dispatcher.relayPayload(sessionCookie, session, responseWriter, request)
	if err != nil {
		log.Printf("dispatch: %s", err)
		dispatcher.terminateConnection(responseWriter, request)
		dispatcher.CloseSession(sessionKey)
		return
	}

	/*
		NOTE: this code cleans up session resources quickly (when the
		      peer closes its persistent connection) but isn't
		      appropriate for the fronted case since the front doesn't
		      necessarily keep a persistent connection open.

		notify := responseWriter.(http.CloseNotifier).CloseNotify()

		go func() {
			<-notify
			dispatcher.CloseSession(cookie)
		}()
	*/
}

func (dispatcher *Dispatcher) relayPayload(sessionCookie *http.Cookie, session *Session, responseWriter http.ResponseWriter, request *http.Request) error {
	body := http.MaxBytesReader(responseWriter, request.Body, MAX_PAYLOAD_LENGTH+1)
	requestBodySize, err := io.Copy(session.psiConn, body)
	if err != nil {
		return errors.New(fmt.Sprintf("writing payload to psiConn: %s", err))
	}

	session.BytesTransferred += requestBodySize

	throttle := dispatcher.config.ThrottleThresholdBytes > 0 &&
		session.IsThrottled &&
		session.BytesTransferred >= dispatcher.config.ThrottleThresholdBytes

	if session.meekProtocolVersion >= MEEK_PROTOCOL_VERSION_2 && session.meekSessionKeySent == false {
		http.SetCookie(responseWriter, sessionCookie)
		session.meekSessionKeySent = true
	}

	if !throttle && session.meekProtocolVersion >= MEEK_PROTOCOL_VERSION_1 {
		responseSize, err := copyWithTimeout(responseWriter, session.psiConn)
		if err != nil {
			return errors.New(fmt.Sprintf("reading payload from psiConn: %s", err))
		}

		session.BytesTransferred += responseSize

	} else {

		reponseMaxPayloadLength := MAX_PAYLOAD_LENGTH

		if throttle {
			time.Sleep(
				time.Duration(dispatcher.config.ThrottleSleepMilliseconds) * time.Millisecond)
			reponseMaxPayloadLength = int(float64(reponseMaxPayloadLength) * dispatcher.config.ThrottleMaxPayloadSizeMultiple)
		}

		buf := make([]byte, reponseMaxPayloadLength)
		session.psiConn.SetReadDeadline(time.Now().Add(TURN_AROUND_TIMEOUT))
		responseSize, err := session.psiConn.Read(buf)
		if err != nil {
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				return errors.New(fmt.Sprintf("reading from psiConn: %s", err))
			}
		}

		responseSize, err = responseWriter.Write(buf[:responseSize])
		if err != nil {
			return errors.New(fmt.Sprintf("writing to response: %s", err))
		}

		session.BytesTransferred += int64(responseSize)
	}

	return nil
}

/*
Relays bytes (e.g., from the remote socket (sshd) to the HTTP response payload)
Uses chunked transfer encoding. The relay is run for a max time period, so as
to not block subsequent requests from being sent (assuming non-HTTP-pipelining).
Also, each read from the source uses the standard turnaround timeout, so that if
no data is available we return no slower than the non-chunked mode.

Adapted from Copy: http://golang.org/src/pkg/io/io.go
*/
func copyWithTimeout(dst io.Writer, src net.Conn) (written int64, err error) {
	startTime := time.Now()
	buffer := make([]byte, 64*1024)
	for {
		src.SetReadDeadline(time.Now().Add(TURN_AROUND_TIMEOUT))
		bytesRead, errRead := src.Read(buffer)
		if bytesRead > 0 {
			bytesWritten, errWrite := dst.Write(buffer[0:bytesRead])
			if bytesWritten > 0 {
				written += int64(bytesWritten)
			}
			if errWrite != nil {
				err = errWrite
				break
			}
			if bytesRead != bytesWritten {
				err = io.ErrShortWrite
				break
			}
		}
		if errRead == io.EOF {
			break
		}
		if e, ok := errRead.(net.Error); ok && e.Timeout() {
			break
		}
		if errRead != nil {
			err = errRead
			break
		}
		totalElapsedTime := time.Now().Sub(startTime) / time.Millisecond
		if totalElapsedTime >= EXTENDED_TURN_AROUND_TIMEOUT {
			break
		}
	}
	return written, err
}

func (dispatcher *Dispatcher) terminateConnection(responseWriter http.ResponseWriter, request *http.Request) {
	http.NotFound(responseWriter, request)

	// Hijack to close socket (after flushing response).
	hijack, ok := responseWriter.(http.Hijacker)
	if !ok {
		log.Printf("webserver doesn't support hijacking")
		return
	}
	conn, buffer, err := hijack.Hijack()
	if err != nil {
		log.Printf("hijack error: %s", err.Error())
		return
	}
	buffer.Flush()
	conn.Close()
}

func generateSessionKey() (token string, err error) {
	max := MAX_SESSION_KEY_LENGTH - MIN_SESSION_KEY_LENGTH

	if max <= 0 {
		err = fmt.Errorf("MAX_SESSION_KEY_LENGHT is less or equal MIN_SESSION_KEY_LENGTH")
		return
	}

	randomInt, err := rand.Int(rand.Reader, big.NewInt(int64(max+1)))
	if err != nil {
		return
	}

	tokenLength := int(randomInt.Uint64()) + MIN_SESSION_KEY_LENGTH

	var bytes = make([]byte, tokenLength)
	rand.Read(bytes)
	alphanumLength := byte(len(ALPHANUMERICAL))
	for i, b := range bytes {
		bytes[i] = ALPHANUMERICAL[b%alphanumLength]
	}

	token = string(bytes)
	return
}

func (dispatcher *Dispatcher) GetSession(request *http.Request, cookie string) (sessKey string, session *Session, err error) {

	if len(cookie) == 0 {
		err = errors.New("cookie is empty")
		return
	}

	dispatcher.lock.RLock()
	session, ok := dispatcher.sessionMap[cookie]
	dispatcher.lock.RUnlock()
	if ok {
		err = nil
		session.Touch()
		return
	}

	// At this point we have either a new session credentials ciphertext
	// or an expired session token.
	// Let's try and get connection credentials from the cookie payload.
	// If one of the following string massaging operations fails we are
	// most likely dealing with an expired session or a malicious request

	obfuscated, err := base64.StdEncoding.DecodeString(cookie)
	if err != nil {
		return
	}

	encrypted, err := dispatcher.crypto.Deobfuscate(obfuscated, dispatcher.config.ObfuscatedKeyword)
	if err != nil {
		return
	}

	cookieJson, err := dispatcher.crypto.Decrypt(encrypted)
	if err != nil {
		return
	}

	clientSessionData, err := parseCookieJSON(cookieJson)
	if err != nil {
		return
	}

	conn, err := net.DialTimeout("tcp", clientSessionData.PsiphonServerAddress, PSI_CONN_DIAL_TIMEOUT)
	if err != nil {
		return
	}

	session = &Session{psiConn: conn, meekProtocolVersion: clientSessionData.MeekProtocolVersion, meekSessionKeySent: false}
	session.Touch()

	geoIpData := dispatcher.doStats(request, clientSessionData.PsiphonClientSessionId)

	if geoIpData != nil {
		_, ok := dispatcher.config.ThrottleRegions[geoIpData.Region]
		session.IsThrottled = ok
	}

	dispatcher.lock.Lock()
	if clientSessionData.MeekProtocolVersion >= MEEK_PROTOCOL_VERSION_2 {
		sessKey, err = generateSessionKey()
		if err != nil {
			return
		}
	} else {
		sessKey = cookie
	}
	dispatcher.sessionMap[sessKey] = session
	dispatcher.lock.Unlock()

	return
}

func parseCookieJSON(cookieJson []byte) (clientSessionData *ClientSessionData, err error) {
	err = json.Unmarshal(cookieJson, &clientSessionData)
	if err != nil {
		err = fmt.Errorf("parseCookieJSON error decoding '%s'", string(cookieJson))
	}
	return
}

func (dispatcher *Dispatcher) doStats(request *http.Request, psiphonClientSessionId string) *GeoIpData {
	// Use Geo info in headers sent by fronts; otherwise use peer IP
	ipAddress := ""
	var geoIpData *GeoIpData

	// Only use headers when sent through TLS (although we're using
	// self signed keys in TLS mode, so man-in-the-middle is technically
	// still possible so "faked stats" is still a risk...?)
	if dispatcher.config.ListenTLS {
		if geoIpData == nil {
			ipAddress = request.Header.Get("True-Client-IP")
			if len(ipAddress) > 0 {
				geoIpData = dispatcher.geoIpRequest(ipAddress)
			}
		}

		if geoIpData == nil {
			ipAddress = request.Header.Get("X-Forwarded-For")
			if len(ipAddress) > 0 {
				geoIpData = dispatcher.geoIpRequest(ipAddress)
			}
		}

		if geoIpData == nil {
			// Cloudflare
			ipAddress = request.Header.Get("Cf-Connecting-Ip")
			if len(ipAddress) > 0 {
				geoIpData = dispatcher.geoIpRequest(ipAddress)
			}
		}

		if geoIpData == nil {
			// Google App Engine
			country := request.Header.Get("X-Appengine-Country")
			city := request.Header.Get("X-Appengine-City")
			if len(country) > 0 || len(city) > 0 {
				// TODO: redis operation
				log.Printf("X-Appengine-Country:%s , X-Appengine-City: %s", country, city)
				geoIpData = &GeoIpData{
					Region: country,
					City:   city,
					Isp:    "None",
				}
			}
		}
	}

	if geoIpData == nil {
		ipAddress = strings.Split(request.RemoteAddr, ":")[0]
		geoIpData = dispatcher.geoIpRequest(ipAddress)
	}

	if geoIpData != nil {
		dispatcher.updateRedis(psiphonClientSessionId, ipAddress, geoIpData)
	}

	return geoIpData
}

func (dispatcher *Dispatcher) geoIpRequest(ipAddress string) (geoIpData *GeoIpData) {
	// Default value is used when request fails
	geoIpData = &GeoIpData{
		Region: "None",
		City:   "None",
		Isp:    "None",
	}
	response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/geoip?ip=%s", dispatcher.config.GeoIpServicePort, ipAddress))
	if err != nil {
		log.Printf("geoIP request failed: %s", err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 200 {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Printf("geoIP response read failed: %s", err)
			return
		}
		err = json.Unmarshal(responseBody, &geoIpData)
		if err != nil {
			log.Printf("geoIP response decode failed: %s", err)
			return
		}
	}
	return
}

func (dispatcher *Dispatcher) updateRedis(psiphonClientSessionId string, ipAddress string, geoIpData *GeoIpData) {
	redisClient, err := redis.DialTimeout(
		"tcp",
		fmt.Sprintf("%s:%d", dispatcher.config.RedisDbHost, dispatcher.config.RedisDbPort),
		time.Duration(1)*time.Second)
	if err != nil {
		log.Printf("connect to redis failed: %s", err)
		return
	}
	defer redisClient.Close()

	geoIpDataJson, err := json.Marshal(geoIpData)
	if err != nil {
		log.Printf("redis json encode failed: %s", err)
		return
	}

	dispatcher.redisSetExpiringValue(
		redisClient,
		dispatcher.config.RedisSessionDbIndex,
		psiphonClientSessionId,
		string(geoIpDataJson),
		dispatcher.config.RedisSessionExpireSeconds)

	if len(ipAddress) > 0 {
		clientIpAddressStrategyValue := dispatcher.calculateClientIpAddressStrategyValue(ipAddress)
		clientIpAddressStrategyValueMap := map[string]int{"client_ip_address_strategy_value": clientIpAddressStrategyValue}

		clientIpAddressStrategyValueJson, err := json.Marshal(clientIpAddressStrategyValueMap)
		if err != nil {
			log.Printf("redis json encode failed: %s", err)
			return
		}

		dispatcher.redisSetExpiringValue(
			redisClient,
			dispatcher.config.RedisDiscoveryDbIndex,
			psiphonClientSessionId,
			string(clientIpAddressStrategyValueJson),
			dispatcher.config.RedisDiscoveryExpireSeconds)
	}
}

func (dispatcher *Dispatcher) redisSetExpiringValue(redisClient *redis.Client, dbIndex int, key string, value string, expirySeconds int) {
	response := redisClient.Cmd("select", dbIndex)
	if response.Err != nil {
		log.Printf("redis select command failed: %s", response.Err)
		return
	}
	response = redisClient.Cmd("set", key, value)
	if response.Err != nil {
		log.Printf("redis set command failed: %s", response.Err)
		return
	}
	response = redisClient.Cmd("expire", key, expirySeconds)
	if response.Err != nil {
		log.Printf("redis expire command failed: %s", response.Err)
		return
	}
}

func (dispatcher *Dispatcher) calculateClientIpAddressStrategyValue(ipAddress string) int {
	// From: psi_ops_discovery.calculate_ip_address_strategy_value:
	//     # Mix bits from all octets of the client IP address to determine the
	//     # bucket. An HMAC is used to prevent pre-calculation of buckets for IPs.
	//     return ord(hmac.new(HMAC_KEY, ip_address, hashlib.sha256).digest()[0])
	mac := hmac.New(sha256.New, []byte(dispatcher.config.ClientIpAddressStrategyValueHmacKey))
	mac.Write([]byte(ipAddress))
	return int(mac.Sum(nil)[0])
}

func (dispatcher *Dispatcher) CloseSession(sessionId string) {
	dispatcher.lock.Lock()
	session, ok := dispatcher.sessionMap[sessionId]
	if ok {
		dispatcher.closeSessionHelper(sessionId, session)
	}
	dispatcher.lock.Unlock()
}

func (dispatcher *Dispatcher) closeSessionHelper(sessionId string, session *Session) {
	// TODO: close the persistent HTTP client connection, if one exists
	session.psiConn.Close()
	delete(dispatcher.sessionMap, sessionId)
}

func (dispatcher *Dispatcher) ExpireSessions() {
	for {
		time.Sleep(MAX_SESSION_STALENESS / 2)
		dispatcher.lock.Lock()
		for sessionId, session := range dispatcher.sessionMap {
			if session.Expired() {
				dispatcher.closeSessionHelper(sessionId, session)
			}
		}
		dispatcher.lock.Unlock()
	}
}

// TimeoutListener adapted from nettimeout (https://gist.github.com/jbardin/9663312)
//
// NOTE:
// - not compatible with http.Server.ReadTimeout (conflicting use of net.Conn.SetReadDeadline)
// - explicitly calls Close() on timeout, to mitigate https://code.google.com/p/go/issues/detail?id=8534;

// TimeoutListener wraps a net.Listener, and gives a place to store the timeout
// parameters. On Accept, it will wrap the net.Conn with our own Conn for us.
type TimeoutListener struct {
	net.Listener
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (l *TimeoutListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// tcpKeepAliveListener functionality from net.http.Server.ListenAndServe
	tcp, ok := c.(*net.TCPConn)
	if ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(TCP_KEEP_ALIVE_PERIOD)
	}
	tc := &TimeoutConn{
		Conn:         c,
		ReadTimeout:  l.ReadTimeout,
		WriteTimeout: l.WriteTimeout,
	}
	return tc, nil
}

// TimeoutConn wraps a net.Conn, and sets a deadline for every read
// and write operation.
type TimeoutConn struct {
	net.Conn
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (c *TimeoutConn) Read(b []byte) (n int, err error) {
	err = c.Conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	if err != nil {
		return 0, err
	}
	n, err = c.Conn.Read(b)
	if err != nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			c.Close()
		}
	}
	return
}

func (c *TimeoutConn) Write(b []byte) (n int, err error) {
	err = c.Conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	if err != nil {
		return 0, err
	}
	n, err = c.Conn.Write(b)
	if err != nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			c.Close()
		}
	}
	return
}

func NewTimeoutListener(l net.Listener, readTimeout, writeTimeout time.Duration) net.Listener {
	tl := &TimeoutListener{
		Listener:     l,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}
	return tl
}

type MeekHTTPServer struct {
	server *http.Server
}

func (httpServer *MeekHTTPServer) ListenAndServe() error {
	addr := httpServer.server.Addr
	if addr == "" {
		addr = ":http"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return httpServer.server.Serve(
		NewTimeoutListener(l, HTTP_CLIENT_READ_TIMEOUT, HTTP_CLIENT_WRITE_TIMEOUT))
}

func (httpServer *MeekHTTPServer) ListenAndServeTLS(certPEMBlock, keyPEMBlock []byte) error {

	addr := httpServer.server.Addr
	if addr == "" {
		addr = ":https"
	}
	tlsConfig := &tls.Config{}
	if httpServer.server.TLSConfig != nil {
		*tlsConfig = *httpServer.server.TLSConfig
	}
	if tlsConfig.NextProtos == nil {
		tlsConfig.NextProtos = []string{"http/1.1"}
	}

	var err error
	tlsConfig.Certificates = make([]tls.Certificate, 1)
	tlsConfig.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	tlsConfig.MinVersion = tls.VersionTLS10
	if err != nil {
		return err
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return httpServer.server.Serve(
		tls.NewListener(
			NewTimeoutListener(l, HTTP_CLIENT_READ_TIMEOUT, HTTP_CLIENT_WRITE_TIMEOUT),
			tlsConfig))
}

func createTLSConfig(host string) (certPEMBlock, keyPEMBlock []byte, err error) {
	now := time.Now()
	tpl := x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(0),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-24 * time.Hour).UTC(),
		NotAfter:              now.AddDate(1, 0, 0).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		Version:               2,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return
	}
	certPEMBlock = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEMBlock = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return
}

func (dispatcher *Dispatcher) Start() {
	// ECC ciphers in golang TLS are significantly heavier on the server's resources
	// Since encryption strength is not as important at this layer (this layer is obfuscation; tunneled SSH provides privacy)
	// we are going to change order of preference of the available ciphersuites in favour of non ECC ones

	mTLSConfig := &tls.Config{
		CipherSuites: []uint16{
			// non ECC ones first
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		},
		PreferServerCipherSuites: true,
	}

	server := &MeekHTTPServer{
		server: &http.Server{
			Addr:      fmt.Sprintf(":%d", dispatcher.config.Port),
			Handler:   dispatcher,
			TLSConfig: mTLSConfig,
		},
	}

	go dispatcher.ExpireSessions()

	if dispatcher.config.ListenTLS {
		cert, privkey, err := createTLSConfig("www.example.org")
		if err != nil {
			log.Fatalf("createTLSConfig failed to create private key and certificate")
		}
		log.Fatal(server.ListenAndServeTLS(cert, privkey))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func NewDispatcher(config *Config) (*Dispatcher, error) {
	var cookiePrivateKey, dummyKey [32]byte
	keydata, err := base64.StdEncoding.DecodeString(config.CookiePrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding config.CookiePrivateKeyBase64: %s", err)
	}

	copy(cookiePrivateKey[:], keydata)
	crypto := crypto.New(dummyKey, cookiePrivateKey)
	dispatcher := &Dispatcher{
		config:     config,
		crypto:     crypto,
		sessionMap: make(map[string]*Session),
	}
	return dispatcher, nil
}

func parseConfigJSON(baseConfig *Config, data []byte) (config *Config, err error) {
	if baseConfig == nil {
		config = &Config{
			GeoIpServicePort:            DEFAULT_GEOIP_SERVICE_PORT,
			RedisDbHost:                 DEFAULT_REDIS_DB_HOST,
			RedisDbPort:                 DEFAULT_REDIS_DB_PORT,
			RedisSessionDbIndex:         DEFAULT_REDIS_SESSION_DB_INDEX,
			RedisSessionExpireSeconds:   DEFAULT_REDIS_SESSION_EXPIRE_SECONDS,
			RedisDiscoveryDbIndex:       DEFAULT_REDIS_DISCOVERY_DB_INDEX,
			RedisDiscoveryExpireSeconds: DEFAULT_REDIS_DISCOVERY_EXPIRE_SECONDS,
		}
	} else {
		config = baseConfig
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		return
	}

	log.Printf("Parsed config: (%+v)", config)
	return
}

func updateConfig(configJSONFilename string, baseConfig *Config) (config *Config, err error) {
	config = baseConfig
	var read []byte
	read, err = ioutil.ReadFile(configJSONFilename)
	if err != nil {
		return
	}

	config, err = parseConfigJSON(baseConfig, read)
	if err != nil {
		log.Fatalf("error parsing config: %s", err)
	}

	return
}

func main() {
	var configJSONFilename string
	var config *Config
	flag.StringVar(&configJSONFilename, "config", "", "JSON config file")
	flag.Parse()
	var err error

	if configJSONFilename == "" {
		log.Fatalf("config file is required, exiting now")
	} else {
		config, err = updateConfig(configJSONFilename, config)
		if err != nil {
			log.Fatalf("error reading configJSONFilename: %s", err)
		}
	}

	// This config overrides file may not exist.
	// Config values specified in this file will override any values specified
	// in the original config file read above.
	config, _ = updateConfig("meek-server.json", config)

	if config.Port == 0 {
		log.Fatalf("port is missing from the config file, exiting now")
	}

	if config.CookiePrivateKeyBase64 == "" {
		log.Fatalf("cookie private key is missing from the config file, exiting now")
	}

	if config.ObfuscatedKeyword == "" {
		log.Fatalf("obfuscation keyword is missing from the config file, exiting now")
	}

	if config.ClientIpAddressStrategyValueHmacKey == "" {
		log.Fatalf("client ip address strategy value hmac key is missing from the config file, exiting now")
	}

	if config.LogFilename != "" {
		f, err := os.OpenFile(config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("error opening log file: %s", err)
		}
		defer f.Close()
		log.SetOutput(f)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	dispatcher, err := NewDispatcher(config)
	if err != nil {
		log.Fatalf("Could not init a new dispatcher: %s", err)
	}

	dispatcher.Start()
}
