// Package tlsdec decrypts TLS streams with the secrets from an NSS key log file, the format that
// SSLKEYLOGFILE and node --tls-keylog write.
package tlsdec

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type random [32]byte

type tls13Secrets struct {
	clientHandshake, serverHandshake []byte
	clientTraffic, serverTraffic     []byte
}

// Keylog holds the secrets of every connection in a key log file, keyed by the client random.
type Keylog struct {
	master map[random][]byte
	tls13  map[random]*tls13Secrets
}

// LoadKeylog reads the key log file at path.
func LoadKeylog(path string) (*Keylog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open key log: err=%w", err)
	}
	defer f.Close()
	return ParseKeylog(f)
}

// ParseKeylog reads a key log. A malformed line is an error, so a truncated file does not
// silently leave connections encrypted.
func ParseKeylog(r io.Reader) (*Keylog, error) {
	kl := &Keylog{master: map[random][]byte{}, tls13: map[random]*tls13Secrets{}}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := kl.addLine(line); err != nil {
			return nil, fmt.Errorf("key log line %d: err=%w", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("failed to read key log: err=%w", err)
	}
	return kl, nil
}

func (kl *Keylog) addLine(line string) error {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return errors.New("want 3 fields")
	}
	cr, err := hex.DecodeString(fields[1])
	if err != nil || len(cr) != len(random{}) {
		return errors.New("bad client random")
	}
	secret, err := hex.DecodeString(fields[2])
	if err != nil || len(secret) == 0 {
		return errors.New("bad secret")
	}
	var key random
	copy(key[:], cr)

	if fields[0] == "CLIENT_RANDOM" {
		kl.master[key] = secret
		return nil
	}
	s := kl.tls13[key]
	if s == nil {
		s = &tls13Secrets{}
		kl.tls13[key] = s
	}
	switch fields[0] {
	case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
		s.clientHandshake = secret
	case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
		s.serverHandshake = secret
	case "CLIENT_TRAFFIC_SECRET_0":
		s.clientTraffic = secret
	case "SERVER_TRAFFIC_SECRET_0":
		s.serverTraffic = secret
	}
	// Other labels (EXPORTER_SECRET, early data) do not carry HTTP, so they are accepted and unused.
	return nil
}
