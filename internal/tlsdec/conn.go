package tlsdec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/jb0n/pcap2har-go/pcap-cli/tcp"
)

const (
	recChangeCipherSpec = 20
	recAlert            = 21
	recHandshake        = 22
	recApplicationData  = 23

	hsClientHello = 1
	hsServerHello = 2
	hsFinished    = 20
	hsKeyUpdate   = 24

	extEncryptThenMAC    = 0x0016
	extSupportedVersions = 0x002b

	maxRecordLen = 1<<14 + 2048

	// partnerGrace is how long a finished stream waits for the other direction to appear before it gives up.
	partnerGrace = 2 * time.Second
)

// helloRetryRandom is the ServerHello random that marks a HelloRetryRequest (RFC 8446 section 4.1.3).
var helloRetryRandom = random(sha256.Sum256([]byte("HelloRetryRequest")))

type record struct {
	typ     byte
	version uint16
	payload []byte
	seen    time.Time
}

type flowKey struct{ net, port gopacket.Flow }

// Conns pairs the two directions of each TLS connection. The two directions reach the reader as separate streams,
// and neither can be decrypted until the ClientHello and the ServerHello are both known.
type Conns struct {
	kl *Keylog

	mtx      sync.Mutex
	conns    map[flowKey]*conn
	outcomes map[string]int
}

// NewConns returns a Conns that decrypts with the secrets in kl.
func NewConns(kl *Keylog) *Conns {
	return &Conns{kl: kl, conns: map[flowKey]*conn{}, outcomes: map[string]int{}}
}

func (c *Conns) count(outcome string) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.outcomes[outcome]++
}

// Summary gives the count of TLS streams per outcome, for one log line at the end of a run.
func (c *Conns) Summary() string {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if len(c.outcomes) == 0 {
		return "tls: no TLS streams"
	}
	parts := make([]string, 0, len(c.outcomes))
	for k, v := range c.outcomes {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(parts)
	return "tls streams: " + strings.Join(parts, " ")
}

// conn is one TLS connection. One mutex covers both directions, because a reader waits on state that the pump of
// the other direction writes.
type conn struct {
	mtx  sync.Mutex
	cond *sync.Cond

	clientRandom *random
	serverRandom *random
	version      uint16
	suiteID      uint16
	etm          bool
	sides        [2]*side // index 0 = client, 1 = server, set when a pump sees its hello
	open, closed int      // streams of this connection that started, and that finished
	graceOver    bool

	keysDone bool
	keysErr  error
	dec      [2]decrypter
	tls13    *tls13Secrets
	suite    *suite
}

type side struct {
	queue  []record
	done   bool
	failed bool
}

func (c *Conns) connFor(a, b gopacket.Flow) *conn {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if cn, ok := c.conns[flowKey{a.Reverse(), b.Reverse()}]; ok {
		return cn
	}
	k := flowKey{a, b}
	cn, ok := c.conns[k]
	if !ok {
		cn = &conn{}
		cn.cond = sync.NewCond(&cn.mtx)
		c.conns[k] = cn
	}
	return cn
}

func (c *Conns) release(a, b gopacket.Flow, cn *conn) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	for _, k := range []flowKey{{a, b}, {a.Reverse(), b.Reverse()}} {
		if c.conns[k] == cn {
			delete(c.conns, k)
		}
	}
}

// Wrap looks at the first bytes of s. When they start a TLS handshake it returns a stream of the decrypted
// application data and true. Otherwise it returns a stream that replays those bytes and false.
func (c *Conns) Wrap(s tcp.Stream, a, b gopacket.Flow) (tcp.Stream, bool) {
	// Register before the peek, which blocks until data arrives, so the other direction can see this one exists.
	cn := c.connFor(a, b)
	cn.mtx.Lock()
	cn.open++
	cn.mtx.Unlock()

	head := make([]byte, 3)
	n, _ := io.ReadFull(s, head) // a short read just means the stream is not TLS
	head = head[:n]
	replay := &replayStream{r: io.MultiReader(bytes.NewReader(head), s), s: s}
	if n < 3 || head[0] != recHandshake || head[1] != 3 {
		c.closeStream(a, b, cn)
		return replay, false
	}

	d := &decStream{c: c, cn: cn, sd: &side{}, role: -1}
	go func() {
		d.pump(replay)
		c.closeStream(a, b, cn)
	}()
	return d, true
}

func (c *Conns) closeStream(a, b gopacket.Flow, cn *conn) {
	cn.mtx.Lock()
	cn.closed++
	release := cn.open == 2 && cn.closed == 2
	if cn.open == 1 && cn.closed == 1 {
		time.AfterFunc(partnerGrace, func() {
			cn.mtx.Lock()
			cn.graceOver = true
			cn.cond.Broadcast()
			cn.mtx.Unlock()
		})
	}
	cn.cond.Broadcast()
	cn.mtx.Unlock()
	if release {
		c.release(a, b, cn)
	}
}

type replayStream struct {
	r io.Reader
	s tcp.Stream
}

func (r *replayStream) Read(p []byte) (int, error) { return r.r.Read(p) }
func (r *replayStream) Seen() (time.Time, error)   { return r.s.Seen() }

// decStream is one direction of a TLS connection. Its pump drains the TCP stream into a queue at once, because the
// assembler blocks on a stream nobody reads, and the other direction still needs to deliver its hello.
type decStream struct {
	c     *Conns
	cn    *conn
	sd    *side
	role  int // 0 client, 1 server, -1 unknown; written under cn.mtx
	plain []byte
	seen  time.Time
	err   error

	encrypted bool   // TLS 1.2: this direction sent ChangeCipherSpec
	hs        []byte // TLS 1.3 handshake bytes, to find where Finished and KeyUpdate end
}

func (d *decStream) pump(r tcp.Stream) {
	hdr := make([]byte, 5)
	var hsBuf []byte
	plainHello := true
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			break
		}
		l := int(binary.BigEndian.Uint16(hdr[3:]))
		if l > maxRecordLen {
			break
		}
		payload := make([]byte, l)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}
		seen, err := r.Seen()
		if err != nil {
			seen = time.Time{}
		}
		rec := record{typ: hdr[0], version: binary.BigEndian.Uint16(hdr[1:]), payload: payload, seen: seen}

		if plainHello && rec.typ == recHandshake {
			hsBuf = append(hsBuf, payload...)
			hsBuf = d.parseHellos(hsBuf)
		}
		if rec.typ == recChangeCipherSpec {
			plainHello = false
		}

		d.cn.mtx.Lock()
		if !d.sd.failed {
			d.sd.queue = append(d.sd.queue, rec)
		}
		d.cn.cond.Broadcast()
		d.cn.mtx.Unlock()
	}
	// Drain what is left so a stream that is not TLS after all cannot block the assembler.
	_, _ = io.Copy(io.Discard, r) // the bytes are unusable either way

	d.cn.mtx.Lock()
	d.sd.done = true
	if d.role < 0 {
		// No hello: this stream started mid-connection, so no key can open it.
		d.sd.failed = true
	}
	d.cn.cond.Broadcast()
	d.cn.mtx.Unlock()
}

// parseHellos reads whole handshake messages out of buf and returns the bytes of a message not yet complete.
func (d *decStream) parseHellos(buf []byte) []byte {
	for len(buf) >= 4 {
		l := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if len(buf) < 4+l {
			return buf
		}
		msg := buf[4 : 4+l]
		switch buf[0] {
		case hsClientHello:
			d.clientHello(msg)
		case hsServerHello:
			d.serverHello(msg)
		}
		buf = buf[4+l:]
	}
	return buf
}

func (d *decStream) setRole(role int) {
	d.cn.mtx.Lock()
	defer d.cn.mtx.Unlock()
	if d.role < 0 {
		d.role = role
		d.cn.sides[role] = d.sd
	}
}

func (d *decStream) clientHello(msg []byte) {
	if len(msg) < 34 {
		return
	}
	var cr random
	copy(cr[:], msg[2:34])
	d.setRole(0)
	d.cn.mtx.Lock()
	d.cn.clientRandom = &cr
	d.cn.cond.Broadcast()
	d.cn.mtx.Unlock()
}

func (d *decStream) serverHello(msg []byte) {
	// version(2) random(32) session_id(1+n) cipher_suite(2) compression(1) extensions(2+n)
	if len(msg) < 35 {
		return
	}
	var sr random
	copy(sr[:], msg[2:34])
	d.setRole(1)
	if sr == helloRetryRandom {
		return
	}
	version := binary.BigEndian.Uint16(msg)
	p := 34 + 1 + int(msg[34])
	if len(msg) < p+3 {
		return
	}
	suiteID := binary.BigEndian.Uint16(msg[p:])
	p += 3
	etm := false
	if len(msg) >= p+2 {
		end := p + 2 + int(binary.BigEndian.Uint16(msg[p:]))
		for p += 2; p+4 <= end && end <= len(msg); {
			typ := binary.BigEndian.Uint16(msg[p:])
			l := int(binary.BigEndian.Uint16(msg[p+2:]))
			body := msg[p+4 : min(p+4+l, len(msg))]
			switch typ {
			case extSupportedVersions:
				if len(body) == 2 {
					version = binary.BigEndian.Uint16(body)
				}
			case extEncryptThenMAC:
				etm = true
			}
			p += 4 + l
		}
	}

	d.cn.mtx.Lock()
	d.cn.serverRandom = &sr
	d.cn.version = version
	d.cn.suiteID = suiteID
	d.cn.etm = etm
	d.cn.cond.Broadcast()
	d.cn.mtx.Unlock()
}

// ready waits until both hellos are known, then derives the keys one time for both directions. Call it with
// cn.mtx held.
func (d *decStream) ready() error {
	cn := d.cn
	for cn.clientRandom == nil || cn.serverRandom == nil {
		if d.sd.done && d.role < 0 {
			return errors.New("no-hello")
		}
		// Both streams finished, or the other never started within the grace: no hello is still to come.
		if cn.closed == cn.open && (cn.open == 2 || cn.graceOver) {
			return errors.New("one-sided")
		}
		cn.cond.Wait()
	}
	if !cn.keysDone {
		cn.keysDone = true
		cn.keysErr = d.c.deriveKeys(cn)
	}
	return cn.keysErr
}

func (c *Conns) deriveKeys(cn *conn) error {
	s, ok := suites[cn.suiteID]
	if !ok {
		return fmt.Errorf("unsupported-suite-%04x", cn.suiteID)
	}
	cn.suite = s
	if cn.version == versionTLS13 {
		sec := c.kl.tls13[*cn.clientRandom]
		if sec == nil || sec.clientHandshake == nil || sec.serverHandshake == nil ||
			sec.clientTraffic == nil || sec.serverTraffic == nil {
			return errors.New("no-key")
		}
		cn.tls13 = sec
		for i, secret := range [][]byte{sec.clientHandshake, sec.serverHandshake} {
			a, err := newAEAD13(s, secret)
			if err != nil {
				return errors.New("bad-key")
			}
			cn.dec[i] = a
		}
		return nil
	}
	master := c.kl.master[*cn.clientRandom]
	if master == nil {
		return errors.New("no-key")
	}
	cd, sd, err := keys12(s, cn.version, master, *cn.clientRandom, *cn.serverRandom, cn.etm)
	if err != nil {
		return errors.New("bad-key")
	}
	cn.dec[0], cn.dec[1] = cd, sd
	return nil
}

// Read gives the decrypted application data. When the stream cannot be decrypted it counts the reason, drops the
// queue, and returns EOF, so the HTTP decoders see a stream that ends.
func (d *decStream) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		d.next()
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}

func (d *decStream) fail(reason string) {
	d.c.count(reason)
	d.cn.mtx.Lock()
	d.sd.failed = true
	d.sd.queue = nil
	d.cn.mtx.Unlock()
	d.err = io.EOF
}

// next decrypts the next queued record into d.plain, or sets d.err.
func (d *decStream) next() {
	cn := d.cn
	cn.mtx.Lock()
	if err := d.ready(); err != nil {
		cn.mtx.Unlock()
		d.fail(err.Error())
		return
	}
	for len(d.sd.queue) == 0 && !d.sd.done {
		cn.cond.Wait()
	}
	if len(d.sd.queue) == 0 {
		cn.mtx.Unlock()
		d.c.count("decrypted")
		d.err = io.EOF
		return
	}
	rec := d.sd.queue[0]
	d.sd.queue = d.sd.queue[1:]
	cn.mtx.Unlock()

	d.seen = rec.seen
	if err := d.open(rec); err != nil {
		d.fail(err.Error())
	}
}

func (d *decStream) open(rec record) error {
	cn := d.cn
	dec := cn.dec[d.role]
	if cn.version == versionTLS13 {
		if rec.typ != recApplicationData {
			return nil // the plaintext hellos and the compatibility ChangeCipherSpec
		}
		typ, plain, err := dec.decrypt(rec.typ, rec.version, rec.payload)
		if err != nil {
			return errors.New("decrypt-failed")
		}
		switch typ {
		case recApplicationData:
			d.plain = plain
		case recHandshake:
			return d.handshake13(plain)
		}
		return nil
	}

	switch rec.typ {
	case recChangeCipherSpec:
		d.encrypted = true
		return nil
	case recApplicationData, recHandshake, recAlert:
		if !d.encrypted {
			return nil // plaintext handshake before ChangeCipherSpec
		}
		typ, plain, err := dec.decrypt(rec.typ, rec.version, rec.payload)
		if err != nil {
			return errors.New("decrypt-failed")
		}
		if typ == recApplicationData {
			d.plain = plain
		}
	}
	return nil
}

// handshake13 follows the encrypted TLS 1.3 handshake. After this direction sends Finished it switches to the
// application traffic secret, and each KeyUpdate moves that secret one step.
func (d *decStream) handshake13(plain []byte) error {
	cn := d.cn
	d.hs = append(d.hs, plain...)
	for len(d.hs) >= 4 {
		l := int(d.hs[1])<<16 | int(d.hs[2])<<8 | int(d.hs[3])
		if len(d.hs) < 4+l {
			return nil
		}
		typ := d.hs[0]
		d.hs = d.hs[4+l:]

		var secret []byte
		switch {
		case typ == hsFinished && d.role == 0 && cn.tls13.clientTraffic != nil:
			secret = cn.tls13.clientTraffic
		case typ == hsFinished && d.role == 1 && cn.tls13.serverTraffic != nil:
			secret = cn.tls13.serverTraffic
		case typ == hsKeyUpdate:
			cur, ok := cn.dec[d.role].(*aead13)
			if !ok || cur.secret == nil {
				return errors.New("key-update-before-finished")
			}
			secret = hkdfExpandLabel(cn.suite.prfHash, cur.secret, "traffic upd", cn.suite.prfHash().Size())
		default:
			continue
		}
		next, err := newAEAD13(cn.suite, secret)
		if err != nil {
			return errors.New("bad-key")
		}
		next.secret = secret
		cn.dec[d.role] = next
	}
	return nil
}

func (d *decStream) Seen() (time.Time, error) {
	if d.seen.IsZero() {
		return time.Time{}, errors.New("no record seen")
	}
	return d.seen, nil
}
