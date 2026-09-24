package reader_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"testing"

	"github.com/andybalholm/brotli"
)

const (
	page     = "<html>device page</html>"
	encoding = "gzip"
)

func compressed(t *testing.T, newWriter func(io.Writer) (io.WriteCloser, error)) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := newWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, page); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A browser saves the decoded body in a HAR, and thingnet replays it with no Content-Encoding.
func TestResponseBodyDecoded(t *testing.T) {
	cases := []struct {
		name, header string
		body         func(*testing.T) []byte
		want         string
	}{
		{"gzip", encoding, func(t *testing.T) []byte {
			return compressed(t, func(w io.Writer) (io.WriteCloser, error) { return gzip.NewWriter(w), nil })
		}, page},
		{"zlib deflate", "deflate", func(t *testing.T) []byte {
			return compressed(t, func(w io.Writer) (io.WriteCloser, error) { return zlib.NewWriter(w), nil })
		}, page},
		{"raw deflate", "deflate", func(t *testing.T) []byte {
			return compressed(t, func(w io.Writer) (io.WriteCloser, error) {
				return flate.NewWriter(w, flate.DefaultCompression)
			})
		}, page},
		{"brotli", "br", func(t *testing.T) []byte {
			return compressed(t, func(w io.Writer) (io.WriteCloser, error) { return brotli.NewWriter(w), nil })
		}, page},
		// A body that does not decode stays as it came.
		{"broken", encoding, func(*testing.T) []byte { return []byte("not compressed") }, "not compressed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body(t)
			req := []byte("GET / HTTP/1.1\r\nHost: device\r\n\r\n")
			resp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\nContent-Length: %d\r\n\r\n",
				tc.header, len(body))), body...)
			_, convs := decode(t, nil, req, resp)
			if len(convs) != 1 || string(convs[0].ResponseBody) != tc.want {
				t.Fatalf("got %+v, want body %q", convs, tc.want)
			}
		})
	}
}
