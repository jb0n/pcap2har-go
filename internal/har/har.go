package har

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jb0n/pcap2har-go/internal/reader"
)

// Creator app that constructed the har output.
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Page struct {
	StartedDateTime time.Time  `json:"startedDateTime"`
	ID              string     `json:"id"`
	Title           string     `json:"title"`
	PageTimings     PageTiming `json:"pageTimings"`
}

type PageTiming struct {
	OnContentLoad float64 `json:"onContentLoad"`
	OnLoad        float64 `json:"onLoad"`
}

type EntryTimings struct {
	Blocked         int `json:"blocked"`
	BlockedQueueing int `json:"_blocked_queueing"`
	Connect         int `json:"connect"`
	DNS             int `json:"dns"`
	Receive         int `json:"receive"`
	Send            int `json:"send"`
	SSL             int `json:"ssl"`
	Wait            int `json:"wait"`
}

type Header KeyValues

type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Expires  time.Time `json:"expires"`
	HTTPOnly bool      `json:"httpOnly"`
	Secure   bool      `json:"secure"`
}

type RequestInfo struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []Header    `json:"headers"`
	QueryString []KeyValues `json:"queryString"`
	Cookies     []Cookie    `json:"cookies"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
	Content     ContentInfo `json:"postData,omitempty"`
}

type ContentInfo struct {
	MimeType string `json:"mimeType"`
	Size     int    `json:"size"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
	// Compression is the bytes the Content-Encoding saved. Only a response sets it.
	Compression *int       `json:"compression,omitempty"`
	Params      []PostData `json:"params,omitempty"`
}

type KeyValues struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PostData struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

type ResponseInfo struct {
	Status       int         `json:"status"`
	StatusText   string      `json:"statusText"`
	HTTPVersion  string      `json:"httpVersion"`
	Headers      []Header    `json:"headers"`
	Cookies      []Cookie    `json:"cookies"`
	Content      ContentInfo `json:"content"`
	RedirectURL  string      `json:"redirectURL"`
	HeadersSize  int         `json:"headersSize"`
	BodySize     int         `json:"bodySize"`
	TransferSize int         `json:"_transferSize"`
	FCGIErrors   []string    `json:"_fcgiErrors,omitempty"`
}

type Entry struct {
	// start of connection
	StartedDateTime time.Time `json:"startedDateTime"`
	// time taken in ns
	// FIXME: perhaps add timings?
	// for true timings we'd need dns time too.
	// could set to -1 initially I guess
	Time            int64        `json:"time"`
	Request         RequestInfo  `json:"request"`
	Response        ResponseInfo `json:"response"`
	ServerIPAddress string       `json:"serverIPAddress"`
	Connection      string       `json:"connection,omitempty"`
	Timings         EntryTimings `json:"timings"`
}

type Har struct {
	Log struct {
		Version string  `json:"version"`
		Creator Creator `json:"creator"`
		Pages   []Page  `json:"pages"`
		Entries []Entry `json:"entries"`
	} `json:"log"`
}

// AddEntry extracts info from HTTP conversations and turns them into a Har Entry.
func (h *Har) AddEntry(v reader.Conversation) {
	if v.Request == nil {
		return
	}
	req := extractRequest(v)
	startTime := v.RequestSeen[0]
	var duration time.Duration
	if len(v.ResponseSeen) > 0 {
		duration = v.ResponseSeen[len(v.ResponseSeen)-1].Sub(startTime)
	} else {
		duration = v.RequestSeen[len(v.RequestSeen)-1].Sub(startTime)
	}
	resp := ResponseInfo{}
	if v.Response != nil {
		mimeTypes, ok := v.Response.Header["Content-Type"]
		var mimeType string
		if ok {
			mimeType = mimeTypes[0]
		}
		headers := extractHeaders(v.ResponseHeaders, v.Response.Header)
		cookieInfo := extractCookies(v.Response.Cookies())
		// A browser reports the decoded size, the bytes on the wire, and the difference as compression.
		saved := len(v.ResponseBody) - v.ResponseWireSize
		content := ContentInfo{
			Size:        len(v.ResponseBody),
			MimeType:    mimeType,
			Text:        string(v.ResponseBody),
			Compression: &saved,
		}
		// JSON strings hold only UTF-8, so a binary body goes in base64, the way a browser saves it.
		if !utf8.Valid(v.ResponseBody) {
			content.Text = base64.StdEncoding.EncodeToString(v.ResponseBody)
			content.Encoding = "base64"
		}
		resp = ResponseInfo{
			Content:     content,
			BodySize:    v.ResponseWireSize,
			Cookies:     cookieInfo,
			Headers:     headers,
			HTTPVersion: v.Response.Proto,
			StatusText:  strings.TrimSpace(strings.TrimPrefix(v.Response.Status, strconv.Itoa(v.Response.StatusCode))),
			Status:      v.Response.StatusCode,
			FCGIErrors:  v.Errors,
		}
	}
	entry := Entry{
		Request:         req,
		Response:        resp,
		StartedDateTime: startTime,
		Time:            duration.Nanoseconds(),
		ServerIPAddress: v.Address.IP.Dst().String(),
		Timings:         EntryTimings{-1, -1, -1, -1, -1, -1, -1, -1},
	}
	h.Log.Entries = append(h.Log.Entries, entry)
}

// FinaliseAndSort sort the requests by time and fill in the summary structures
// (pages).
func (h *Har) FinaliseAndSort() {
	entries := h.Log.Entries
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].StartedDateTime.Before(entries[j].StartedDateTime)
	})

	for i, entry := range entries {
		id := fmt.Sprintf("page_%d", i+1)
		h.Log.Pages = append(h.Log.Pages, Page{
			ID:              id,
			Title:           entry.Request.URL,
			StartedDateTime: entry.StartedDateTime,
			PageTimings:     PageTiming{-1, -1},
		})
	}
}

func extractCookies(cookies []*http.Cookie) []Cookie {
	cookieInfo := make([]Cookie, len(cookies))
	for i, c := range cookies {
		cookieInfo[i] = Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Expires:  c.Expires,
			HTTPOnly: c.HttpOnly,
			Secure:   c.Secure,
		}
	}
	return cookieInfo
}

// extractHeaders lists the headers the way a browser HAR does: each name as sent, sorted by name (byte order),
// and a repeated name in wire order. The http.Header map is the fallback for a message with no raw lines; it holds
// canonical names only.
func extractHeaders(raw []reader.RawHeader, header http.Header) []Header {
	var headers []Header
	if raw != nil {
		for _, h := range raw {
			headers = append(headers, Header{Name: h.Name, Value: h.Value})
		}
	} else {
		for k, values := range header {
			for _, v := range values {
				headers = append(headers, Header{Name: k, Value: v})
			}
		}
	}
	sort.SliceStable(headers, func(i, j int) bool { return headers[i].Name < headers[j].Name })
	return headers
}

// formParams lists the fields of a urlencoded body in body order. Request.PostForm is a map and loses it.
func formParams(body string) []PostData {
	var out []PostData
	for _, kv := range queryPairs(body) {
		out = append(out, PostData{Name: kv.Name, Value: kv.Value})
	}
	return out
}

// multipartParams lists the parts of a multipart body in body order. A part that does not read ends the list, the
// way a truncated capture ends.
func multipartParams(mimeType string, body []byte) []PostData {
	_, mp, err := mime.ParseMediaType(mimeType)
	if err != nil || mp["boundary"] == "" {
		return nil
	}
	var out []PostData
	r := multipart.NewReader(bytes.NewReader(body), mp["boundary"])
	for {
		part, err := r.NextPart()
		if err != nil {
			return out
		}
		data, err := io.ReadAll(part)
		if err != nil {
			return out
		}
		pd := PostData{Name: part.FormName(), Value: string(data), FileName: part.FileName()}
		if pd.FileName != "" {
			pd.ContentType = part.Header.Get("Content-Type")
		}
		out = append(out, pd)
	}
}

// queryPairs lists the query parameters in the order the URL holds them. URL.Query is a map and loses it.
func queryPairs(rawQuery string) []KeyValues {
	var out []KeyValues
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if uk, err := url.QueryUnescape(k); err == nil {
			k = uk
		}
		if uv, err := url.QueryUnescape(v); err == nil {
			v = uv
		}
		out = append(out, KeyValues{Name: k, Value: v})
	}
	return out
}

func extractRequest(v reader.Conversation) RequestInfo {
	reqheaders := extractHeaders(v.RequestHeaders, v.Request.Header)
	// net/http moves Host out of the header map, so only the fallback path needs it back.
	if v.RequestHeaders == nil && v.Request.Host != "" {
		reqheaders = append(reqheaders, Header{Name: "Host", Value: v.Request.Host})
		sort.SliceStable(reqheaders, func(i, j int) bool { return reqheaders[i].Name < reqheaders[j].Name })
	}
	cookieInfo := extractCookies(v.Request.Cookies())
	queryString := queryPairs(v.Request.URL.RawQuery)
	var mimeType string
	mimeTypes, ok := v.Request.Header["Content-Type"]
	if ok {
		mimeType = mimeTypes[0]
	}
	var params []PostData
	processedMimeType := mimeType
	if idx := strings.Index(processedMimeType, ";"); idx >= 0 {
		processedMimeType = processedMimeType[0:idx]
	}
	switch processedMimeType {
	case "application/x-www-form-urlencoded":
		params = formParams(string(v.RequestBody))
	case "multipart/form-data":
		params = multipartParams(mimeType, v.RequestBody)
	}
	if v.Request.URL.Host == "" {
		v.Request.URL.Host = v.Request.Host
	}
	if v.Request.TLS == nil {
		v.Request.URL.Scheme = "http"
	} else {
		v.Request.URL.Scheme = "https"
	}
	return RequestInfo{
		Cookies:     cookieInfo,
		Headers:     reqheaders,
		HTTPVersion: v.Request.Proto,
		Method:      v.Request.Method,
		URL:         v.Request.URL.String(),
		QueryString: queryString,
		Content: ContentInfo{
			Size:     len(v.RequestBody),
			MimeType: mimeType,
			Text:     string(v.RequestBody),
			Params:   params,
		},
	}
}
