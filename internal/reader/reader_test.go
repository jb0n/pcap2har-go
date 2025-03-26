package reader_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gopacket/gopacket"
	"github.com/jb0n/pcap2har-go/internal/reader"
)

// need a fake reader to emulate getting requests in dribs and drabs as we
// would in reality.
type fakeReader struct {
	data [](io.Reader)
	pos  int
}

func newReader(data []string) *fakeReader {
	readers := make([](io.Reader), len(data))
	for i := range data {
		readers[i] = strings.NewReader(data[i])
	}
	pos := 0
	if len(data) == 0 {
		// special case if we have no data
		// so we return EOF
		pos = 1
	}
	return &fakeReader{data: readers, pos: pos}
}

func (f fakeReader) Read(p []byte) (n int, err error) {
	if len(f.data) < f.pos {
		return 0, io.EOF
	}

	n, err = f.data[f.pos].Read(p)
	if err == io.EOF {
		f.pos++
		if f.pos < len(f.data) {
			n, err = f.data[f.pos].Read(p)
		}
	}
	return
}

func (f fakeReader) Seen() (time.Time, error) {
	return time.Time{}, nil
}

func TestHTTPStreamRead(t *testing.T) {
	req := newReader([]string{"GET / HTTP/1.1\r\n\r\n", "GET /next HTTP/1.1\r\n\r\n"})
	response := newReader([]string{
		strings.Join([]string{"HTTP/1.1 200 OK",
			"Access-Control-Allow-Origin: *",
			"Content-Type: application/json; charset=utf-8",
			"Content-Length: 2",
			"Date: Tue, 19 May 2020 15:10:48 GMT",
			"Connection: keep-alive",
			"",
			"{}"},
			"\r\n",
		),
		strings.Join([]string{"HTTP/1.1 200 OK",
			"Access-Control-Allow-Origin: *",
			"Content-Type: application/json; charset=utf-8",
			"Content-Length: 2",
			"Date: Tue, 19 May 2020 15:10:49 GMT",
			"Connection: keep-alive",
			"",
			"--"},
			"\r\n",
		),
	})
	ipFlow := gopacket.NewFlow(1, []byte{0x7f, 0x0, 0x0, 0x1}, []byte{0x7f,
		0x0, 0x0, 0x1})
	portFlow := gopacket.NewFlow(4, []byte{0x23, 0x36}, []byte{0xa8, 0x0})

	r := reader.New()
	r.ReadStream(req, ipFlow, portFlow, nil)
	r.ReadStream(response, ipFlow.Reverse(), portFlow.Reverse(), nil)

	expected := []reader.Conversation{
		{
			Address: reader.ConversationAddress{IP: ipFlow, Port: portFlow},
			Request: &http.Request{
				Method:     "GET",
				URL:        &url.URL{Path: "/"},
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{},
				Close:      true,
				Body:       http.NoBody,
				RequestURI: "/",
			},
			Response: &http.Response{
				Status:     "200 OK",
				StatusCode: 200,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Access-Control-Allow-Origin": {"*"},
					"Connection":                  {"keep-alive"},
					"Content-Length":              {"2"},
					"Content-Type":                {"application/json; charset=utf-8"},
					"Date":                        {"Tue, 19 May 2020 15:10:48 GMT"},
				},
				ContentLength: 2,
			},
			RequestBody:  []byte(""),
			ResponseBody: []byte("{}"),
			RequestSeen:  []time.Time{{}},
			ResponseSeen: []time.Time{{}},
		},
		{
			Address: reader.ConversationAddress{IP: ipFlow, Port: portFlow},
			Request: &http.Request{
				Method:     "GET",
				URL:        &url.URL{Path: "/next"},
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{},
				Close:      true,
				Body:       http.NoBody,
				RequestURI: "/",
			},
			RequestSeen:  []time.Time{{}},
			ResponseSeen: []time.Time{{}},
			Response: &http.Response{
				Status:     "200 OK",
				StatusCode: 200,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Access-Control-Allow-Origin": {"*"},
					"Connection":                  {"keep-alive"},
					"Content-Length":              {"2"},
					"Content-Type":                {"application/json; charset=utf-8"},
					"Date":                        {"Tue, 19 May 2020 15:10:49 GMT"},
				},
				ContentLength: 2,
			},
			RequestBody:  []byte(""),
			ResponseBody: []byte("--"),
		},
	}

	if diff := cmp.Diff(r.GetConversations(), expected,
		cmp.Comparer(requestCompare),
		cmp.Comparer(flowCompare),
		cmpopts.IgnoreFields(http.Response{}, "Body"),
	); diff != "" {
		t.Errorf("Conversations don't match (-got +expected):\n%s\n", diff)
	}
}

func requestCompare(x, y http.Request) bool {
	// FIXME: need to compare Header too
	return x.Method == y.Method &&
		*x.URL == *y.URL &&
		x.Host == y.Host &&
		x.Proto == y.Proto &&
		x.ProtoMinor == y.ProtoMinor &&
		x.ProtoMajor == y.ProtoMajor
}

func flowCompare(x, y gopacket.Flow) bool {
	return x.String() == y.String()
}
