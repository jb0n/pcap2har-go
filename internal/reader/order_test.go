package reader_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jb0n/pcap2har-go/internal/har"
)

// A browser HAR keeps each header name as sent, sorts the headers by name in byte order, keeps a repeated name in
// wire order, and keeps the query string in URL order. The output must be the same on every run.
func TestHeaderAndQueryOrder(t *testing.T) {
	req := []byte("GET /cgi?b=2&a=1&b=3 HTTP/1.1\r\n" +
		"User-Agent: test\r\nsec-ch-ua: x\r\nHost: device\r\nAccept: */*\r\n\r\n")
	resp := []byte("HTTP/1.1 401 Unauthorized\r\n" +
		"WWW-Authenticate: Digest realm=\"cam\"\r\n" +
		"Set-Cookie: first=1\r\n" +
		"ETag: \"abc\"\r\n" +
		"X-Folded: one\r\n two\r\n" +
		"Set-Cookie: second=2\r\n" +
		"Content-Length: 0\r\n\r\n")
	_, convs := decode(t, nil, req, resp)
	if len(convs) != 1 {
		t.Fatalf("got %d conversations", len(convs))
	}

	var h har.Har
	h.AddEntry(convs[0])
	e := h.Log.Entries[0]

	names := func(hs []har.Header) []string {
		var out []string
		for _, x := range hs {
			out = append(out, x.Name+": "+x.Value)
		}
		return out
	}
	wantReq := []string{"Accept: */*", "Host: device", "User-Agent: test", "sec-ch-ua: x"}
	if diff := cmp.Diff(wantReq, names(e.Request.Headers)); diff != "" {
		t.Errorf("request headers (-want +got):\n%s", diff)
	}
	wantResp := []string{
		"Content-Length: 0", `ETag: "abc"`, "Set-Cookie: first=1", "Set-Cookie: second=2",
		`WWW-Authenticate: Digest realm="cam"`, "X-Folded: one two",
	}
	if diff := cmp.Diff(wantResp, names(e.Response.Headers)); diff != "" {
		t.Errorf("response headers (-want +got):\n%s", diff)
	}
	wantQuery := []har.KeyValues{{Name: "b", Value: "2"}, {Name: "a", Value: "1"}, {Name: "b", Value: "3"}}
	if diff := cmp.Diff(wantQuery, e.Request.QueryString); diff != "" {
		t.Errorf("query string (-want +got):\n%s", diff)
	}
}

// Form fields keep body order too. Request.PostForm is a map.
func TestFormParamOrder(t *testing.T) {
	cases := []struct {
		name, contentType, body string
		want                    []har.PostData
	}{
		{"urlencoded", "application/x-www-form-urlencoded", "zeta=1&alpha=a+b&zeta=2",
			[]har.PostData{{Name: "zeta", Value: "1"}, {Name: "alpha", Value: "a b"}, {Name: "zeta", Value: "2"}}},
		{"multipart", "multipart/form-data; boundary=XX",
			"--XX\r\nContent-Disposition: form-data; name=\"z\"\r\n\r\n1\r\n" +
				"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n" +
				"--XX\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n2\r\n--XX--\r\n",
			[]har.PostData{{Name: "z", Value: "1"}, {Name: "f", Value: "hi", FileName: "a.bin", ContentType: "text/plain"},
				{Name: "a", Value: "2"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := []byte("POST /login HTTP/1.1\r\nHost: device\r\nContent-Type: " + tc.contentType +
				"\r\nContent-Length: " + itoa(len(tc.body)) + "\r\n\r\n" + tc.body)
			resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			_, convs := decode(t, nil, req, resp)
			if len(convs) != 1 {
				t.Fatalf("got %d conversations", len(convs))
			}
			var h har.Har
			h.AddEntry(convs[0])
			if diff := cmp.Diff(tc.want, h.Log.Entries[0].Request.Content.Params); diff != "" {
				t.Errorf("params (-want +got):\n%s", diff)
			}
		})
	}
}
