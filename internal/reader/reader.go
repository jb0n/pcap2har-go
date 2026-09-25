package reader

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly/tcpreader"
	"github.com/jb0n/pcap2har-go/internal/tlsdec"
	"github.com/jb0n/pcap2har-go/pcap-cli/tcp"
)

type HTTPConversationReaders struct {
	mu            sync.Mutex
	conversations map[ConversationAddress][]Conversation
	tls           *tlsdec.Conns
}

type ConversationAddress struct {
	IP, Port gopacket.Flow
}
type Conversation struct {
	Address ConversationAddress
	Request *http.Request
	// RequestHeaders and ResponseHeaders keep each header name as sent, in wire order.
	RequestHeaders  []RawHeader
	RequestBody     []byte
	Response        *http.Response
	ResponseHeaders []RawHeader
	ResponseBody    []byte
	// ResponseWireSize is the body length before the Content-Encoding came off.
	ResponseWireSize int
	RequestSeen      []time.Time
	ResponseSeen     []time.Time
	// FastCGI info if present
	Errors []string
}

func New() *HTTPConversationReaders {
	conversations := make(map[ConversationAddress][]Conversation)
	return &HTTPConversationReaders{
		conversations: conversations,
	}
}

// SetKeylogFile makes the reader decrypt TLS streams with the secrets in the NSS key log at path.
func (h *HTTPConversationReaders) SetKeylogFile(path string) error {
	kl, err := tlsdec.LoadKeylog(path)
	if err != nil {
		return err
	}
	h.tls = tlsdec.NewConns(kl)
	return nil
}

// TLSSummary counts the TLS streams per outcome. It is empty when no key log is set.
func (h *HTTPConversationReaders) TLSSummary() string {
	if h.tls == nil {
		return ""
	}
	return h.tls.Summary()
}

type streamDecoder func(*tcp.SavePointReader, *tcp.TimeCaptureReader, gopacket.Flow, gopacket.Flow) error

func drain(spr *tcp.SavePointReader, _ *tcp.TimeCaptureReader, _, _ gopacket.Flow) error {
	tcpreader.DiscardBytesToEOF(spr)
	return nil
}

// ReadStream tries to read tcp connections and extract HTTP conversations.
func (h *HTTPConversationReaders) ReadStream(r tcp.Stream, a, b gopacket.Flow, completed chan interface{}) {
	isTLS := false
	if h.tls != nil {
		r, isTLS = h.tls.Wrap(r, a, b)
	}
	t := tcp.NewTimeCaptureReader(r)
	spr := tcp.NewSavePointReader(t)
	decoders := []streamDecoder{
		func(spr *tcp.SavePointReader, t *tcp.TimeCaptureReader, a, b gopacket.Flow) error {
			return h.readHTTPRequest(spr, t, a, b, isTLS)
		},
		h.ReadHTTPResponse,
		h.ReadFCGIRequest,
		drain,
	}
	for {
		for i, decode := range decoders {
			err := decode(spr, t, a, b)
			if err == nil {
				break
			}
			if err == io.EOF {
				return
			} else if err != nil {
				// don't need to restore before the last one
				if i+1 < len(decoders) {
					// can discard the save point on the final restore
					spr.Restore(i < len(decoders))
				}
			}
		}
		t.Reset()
	}
}

func (h *HTTPConversationReaders) GetConversations() []Conversation {
	var conversations []Conversation
	for _, c := range h.conversations {
		conversations = append(conversations, c...)
	}
	return conversations
}

// ReadHTTPResponse try to read the stream as an HTTP response.
func (h *HTTPConversationReaders) ReadHTTPResponse(spr *tcp.SavePointReader, t *tcp.TimeCaptureReader, a, b gopacket.Flow) error {
	hc := &headerCapture{}
	buf := bufio.NewReader(io.TeeReader(spr, hc))

	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		return err
	}

	spr.SavePoint()
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	// unexpected EOF reading trailer seems to indicate truncated stream when
	// dealing with chunked encdoing.  If we fall back to not reading it, we
	// still have the same basic output, just with all the chunking arterfacts.
	if err != nil && err.Error() != "http: unexpected EOF reading trailer" {
		spr.Restore(true)
		buf = bufio.NewReader(spr)
		body, err = ioutil.ReadAll(buf)
		if err != nil {
			log.Println("Got an error trying to read it raw, let's just discard")
			tcpreader.DiscardBytesToEOF(buf)
		}
	}
	wireSize := len(body)
	if err == nil || err.Error() == "http: unexpected EOF reading trailer" {
		body = decodeBody(res.Header.Get("Content-Encoding"), body)
	}
	h.addResponse(a, b, res, hc.headers(), body, wireSize, t.Seen())
	return err
}

// decodeBody removes the Content-Encoding, the way a browser does before it saves a HAR. A body that does not
// decode stays as it came, so a truncated capture still shows what arrived.
func decodeBody(encoding string, body []byte) []byte {
	var r io.Reader
	var err error
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		// RFC 9110 says zlib, but some servers send raw deflate.
		r, err = zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			r, err = flate.NewReader(bytes.NewReader(body)), nil
		}
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	default:
		return body
	}
	if err != nil {
		return body
	}
	decoded, err := io.ReadAll(r)
	if err != nil {
		return body
	}
	return decoded
}

// ReadHTTPRequest try to read the stream as an HTTP request.
func (h *HTTPConversationReaders) ReadHTTPRequest(spr *tcp.SavePointReader, t *tcp.TimeCaptureReader, a, b gopacket.Flow) error {
	return h.readHTTPRequest(spr, t, a, b, false)
}

func (h *HTTPConversationReaders) readHTTPRequest(
	spr *tcp.SavePointReader, t *tcp.TimeCaptureReader, a, b gopacket.Flow, isTLS bool,
) error {
	spr.SavePoint()
	hc := &headerCapture{}
	buf := bufio.NewReader(io.TeeReader(spr, hc))

	req, err := http.ReadRequest(buf)
	if err != nil {
		return err
	}

	if isTLS {
		// The HAR writer picks the https scheme from a non-nil TLS state.
		req.TLS = &tls.ConnectionState{}
	}
	spr.SavePoint()
	defer req.Body.Close()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		spr.Restore(true)
		buf = bufio.NewReader(spr)
		body, err = ioutil.ReadAll(buf)
		if err != nil {
			log.Println("Got an error trying to read it raw, let's just discard")
			tcpreader.DiscardBytesToEOF(buf)
		}
	}

	h.addRequest(a, b, req, hc.headers(), body, t.Seen())
	return err
}

func (h *HTTPConversationReaders) addRequest(
	a, b gopacket.Flow, req *http.Request, headers []RawHeader, body []byte, seen []time.Time,
) {
	address := ConversationAddress{IP: a, Port: b}
	h.mu.Lock()
	defer h.mu.Unlock()
	conversations := h.conversations[address]
	for n := 0; n < len(conversations); n++ {
		c := conversations[n]
		if conversations[n].Request == nil {
			c.Request = req
			c.RequestHeaders = headers
			c.RequestBody = body
			c.RequestSeen = seen
			h.conversations[address][n] = c
			return
		}
	}
	h.conversations[address] = append(h.conversations[address], Conversation{
		Address:        address,
		Request:        req,
		RequestHeaders: headers,
		RequestBody:    body,
		RequestSeen:    seen,
	})
}

func (h *HTTPConversationReaders) addErrorToResponse(a, b gopacket.Flow, errString string) {
	h.updateResponse(a, b, func(c *Conversation) {
		c.Errors = append(c.Errors, errString)
	})
}

func (h *HTTPConversationReaders) addResponse(
	a, b gopacket.Flow, res *http.Response, headers []RawHeader, body []byte, wireSize int, seen []time.Time,
) {
	h.updateResponse(a, b, func(c *Conversation) {
		c.Response = res
		c.ResponseHeaders = headers
		c.ResponseBody = body
		c.ResponseWireSize = wireSize
		c.ResponseSeen = seen
	})
}

func (h *HTTPConversationReaders) updateResponse(a, b gopacket.Flow, update func(*Conversation)) {
	address := ConversationAddress{IP: a.Reverse(), Port: b.Reverse()}
	h.mu.Lock()
	defer h.mu.Unlock()
	conversations := h.conversations[address]
	for n := 0; n < len(conversations); n++ {
		c := conversations[n]
		if conversations[n].Response == nil {
			update(&c)
			h.conversations[address][n] = c
			return
		}
	}
	// The two directions decode in separate goroutines, so a response can arrive before its request. It takes the
	// next slot, and addRequest fills the request into the first slot that lacks one, so the nth request still
	// pairs with the nth response.
	c := Conversation{
		Address: address,
	}
	update(&c)
	h.conversations[address] = append(h.conversations[address], c)
}
