package reader_test

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jb0n/pcap2har-go/internal/reader"
)

// chunkStream feeds a recorded direction to the reader in small reads, the way reassembly delivers packets.
type chunkStream struct {
	r *bytes.Reader
}

func (c *chunkStream) Read(p []byte) (int, error) {
	if len(p) > 97 {
		p = p[:97]
	}
	return c.r.Read(p)
}

func (c *chunkStream) Seen() (time.Time, error) { return time.Unix(1700000000, 0), nil }

type recConn struct {
	net.Conn
	mtx sync.Mutex
	out bytes.Buffer
}

func (r *recConn) Write(p []byte) (int, error) {
	r.mtx.Lock()
	r.out.Write(p)
	r.mtx.Unlock()
	return r.Conn.Write(p)
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// session runs two HTTP exchanges over TLS and returns the bytes each side sent.
func session(t *testing.T, version uint16, suite uint16, keylog io.Writer) ([]byte, []byte) {
	t.Helper()
	cp, sp := net.Pipe()
	cr, sr := &recConn{Conn: cp}, &recConn{Conn: sp}
	cfg := &tls.Config{MinVersion: version, MaxVersion: version}
	if suite != 0 {
		cfg.CipherSuites = []uint16{suite}
	}
	scfg := cfg.Clone()
	scfg.Certificates = []tls.Certificate{testCert(t)}
	ccfg := cfg.Clone()
	ccfg.InsecureSkipVerify = true
	ccfg.KeyLogWriter = keylog

	errc := make(chan error, 1)
	go func() {
		srv := tls.Server(sr, scfg)
		br := bufio.NewReader(srv)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				errc <- srv.Close()
				return
			}
			body, _ := io.ReadAll(req.Body)
			resp := "reply to " + req.URL.Path + " " + string(body)
			_, err = io.WriteString(srv, "HTTP/1.1 200 OK\r\nContent-Length: "+
				itoa(len(resp))+"\r\n\r\n"+resp)
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	cli := tls.Client(cr, ccfg)
	br := bufio.NewReader(cli)
	for _, req := range []string{
		"GET /login HTTP/1.1\r\nHost: device\r\n\r\n",
		"POST /config HTTP/1.1\r\nHost: device\r\nContent-Length: 5\r\n\r\nhello",
	} {
		if _, err := io.WriteString(cli, req); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if err := cli.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatal(err)
	}
	return cr.out.Bytes(), sr.out.Bytes()
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

func decode(t *testing.T, keylog []byte, c2s, s2c []byte) (*reader.HTTPConversationReaders, []reader.Conversation) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.log")
	if err := os.WriteFile(path, keylog, 0o600); err != nil {
		t.Fatal(err)
	}
	r := reader.New()
	if err := r.SetKeylogFile(path); err != nil {
		t.Fatal(err)
	}
	nf := gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2})
	pf := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0xc0, 0x01}, []byte{0x01, 0xbb})

	var wg sync.WaitGroup
	for _, d := range []struct {
		data   []byte
		nf, pf gopacket.Flow
	}{{c2s, nf, pf}, {s2c, nf.Reverse(), pf.Reverse()}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.ReadStream(&chunkStream{r: bytes.NewReader(d.data)}, d.nf, d.pf, nil)
		}()
	}
	wg.Wait()
	return r, r.GetConversations()
}

func TestTLSDecrypt(t *testing.T) {
	cases := []struct {
		name    string
		version uint16
		suite   uint16
	}{
		{"tls13", tls.VersionTLS13, 0},
		{"tls12-aes128-gcm", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{"tls12-aes256-gcm", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		{"tls12-chacha", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		{"tls12-cbc-sha", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		{"tls12-cbc-sha256", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256},
		{"tls11-cbc", tls.VersionTLS11, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		{"tls10-cbc", tls.VersionTLS10, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var kl bytes.Buffer
			c2s, s2c := session(t, tc.version, tc.suite, &kl)
			r, convs := decode(t, kl.Bytes(), c2s, s2c)

			got := map[string]string{}
			for _, c := range convs {
				if c.Request == nil || c.Response == nil {
					t.Fatalf("half a conversation: %+v", c)
				}
				if c.Request.TLS == nil {
					t.Errorf("%s: request not marked TLS", c.Request.URL.Path)
				}
				got[c.Request.URL.Path] = string(c.ResponseBody)
			}
			want := map[string]string{"/login": "reply to /login ", "/config": "reply to /config hello"}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s: got %q, want %q (summary: %s)", k, got[k], v, r.TLSSummary())
				}
			}
			if !strings.Contains(r.TLSSummary(), "decrypted=2") {
				t.Errorf("summary: %s", r.TLSSummary())
			}
		})
	}
}

func TestTLSNoKey(t *testing.T) {
	c2s, s2c := session(t, tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, io.Discard)
	r, convs := decode(t, nil, c2s, s2c)
	if len(convs) != 0 {
		t.Errorf("got %d conversations from a connection with no key", len(convs))
	}
	if !strings.Contains(r.TLSSummary(), "no-key=2") {
		t.Errorf("summary: %s", r.TLSSummary())
	}
}

func TestTLSOneSided(t *testing.T) {
	var kl bytes.Buffer
	c2s, _ := session(t, tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &kl)
	path := filepath.Join(t.TempDir(), "keys.log")
	if err := os.WriteFile(path, kl.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	r := reader.New()
	if err := r.SetKeylogFile(path); err != nil {
		t.Fatal(err)
	}
	nf := gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2})
	pf := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0xc0, 0x01}, []byte{0x01, 0xbb})
	r.ReadStream(&chunkStream{r: bytes.NewReader(c2s)}, nf, pf, nil)
	if !strings.Contains(r.TLSSummary(), "one-sided=1") {
		t.Errorf("summary: %s", r.TLSSummary())
	}
}

func TestPlainHTTPWithKeylog(t *testing.T) {
	req := []byte("GET /status HTTP/1.1\r\nHost: device\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	_, convs := decode(t, nil, req, resp)
	if len(convs) != 1 || convs[0].Request.TLS != nil || string(convs[0].ResponseBody) != "ok" {
		t.Fatalf("plain HTTP changed under a key log: %+v", convs)
	}
}

func TestBadKeylog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.log")
	if err := os.WriteFile(path, []byte("CLIENT_RANDOM nothex 00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reader.New().SetKeylogFile(path); err == nil {
		t.Fatal("a malformed key log loaded")
	}
}
