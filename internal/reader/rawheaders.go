package reader

import (
	"bytes"
	"strings"
)

// RawHeader is one header line as it came on the wire. net/http rewrites every name into its canonical form
// (ETag becomes Etag, WWW-Authenticate becomes Www-Authenticate), and a browser HAR keeps the name as sent.
type RawHeader struct {
	Name  string
	Value string
}

// headerCapture is a writer that keeps the bytes of one message up to the end of its header block, and drops the
// rest, so a large body is not held two times.
type headerCapture struct {
	buf  bytes.Buffer
	done bool
}

func (c *headerCapture) Write(p []byte) (int, error) {
	if !c.done {
		c.buf.Write(p)
		if bytes.Contains(c.buf.Bytes(), []byte("\r\n\r\n")) || bytes.Contains(c.buf.Bytes(), []byte("\n\n")) {
			c.done = true
		}
	}
	return len(p), nil
}

// headers parses the header lines after the start line, in wire order. A line that starts with a space or a tab
// continues the value of the line before it (RFC 9112 obs-fold).
func (c *headerCapture) headers() []RawHeader {
	var out []RawHeader
	lines := strings.Split(c.buf.String(), "\n")
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if i == 0 {
			continue // the request line or the status line
		}
		if line == "" {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && len(out) > 0 {
			out[len(out)-1].Value += " " + strings.TrimSpace(line)
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out = append(out, RawHeader{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	return out
}
