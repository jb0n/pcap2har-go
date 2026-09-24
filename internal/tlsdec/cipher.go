package tlsdec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // old lab devices still negotiate 3DES, and a capture must read them
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // CBC suites of TLS 1.0 to 1.2 MAC with SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	versionTLS10 = 0x0301
	versionTLS11 = 0x0302
	versionTLS12 = 0x0303
	versionTLS13 = 0x0304
)

type suiteKind int

const (
	kindGCM suiteKind = iota
	kindChaCha
	kindCBC
)

type suite struct {
	kind    suiteKind
	keyLen  int
	block   func([]byte) (cipher.Block, error)
	macHash func() hash.Hash // CBC only
	prfHash func() hash.Hash // TLS 1.2 PRF, and the TLS 1.3 HKDF hash
	tls13   bool
}

func (s *suite) macLen() int {
	if s.macHash == nil {
		return 0
	}
	return s.macHash().Size()
}

// fixedIVLen is the IV length the key block holds. CBC in TLS 1.1 and later sends the IV in each record, so the
// key block IV only matters for TLS 1.0.
func (s *suite) fixedIVLen() int {
	switch s.kind {
	case kindGCM:
		if s.tls13 {
			return 12
		}
		return 4
	case kindChaCha:
		return 12
	default:
		b, err := s.block(make([]byte, s.keyLen))
		if err != nil {
			return 0
		}
		return b.BlockSize()
	}
}

func gcmSuite(keyLen int, h func() hash.Hash) *suite {
	return &suite{kind: kindGCM, keyLen: keyLen, block: aes.NewCipher, prfHash: h}
}

func cbcSuite(keyLen int, blk func([]byte) (cipher.Block, error), mac func() hash.Hash) *suite {
	prf := sha256.New
	if mac().Size() == sha512.Size384 {
		prf = sha512.New384
	}
	return &suite{kind: kindCBC, keyLen: keyLen, block: blk, macHash: mac, prfHash: prf}
}

var chachaSuite = &suite{kind: kindChaCha, keyLen: chacha20poly1305.KeySize, prfHash: sha256.New}

// suites maps the IANA cipher suite id to its record protection. The key exchange does not matter here, because the
// key log already holds the secret it produced.
var suites = map[uint16]*suite{
	0x1301: {kind: kindGCM, keyLen: 16, block: aes.NewCipher, prfHash: sha256.New, tls13: true},
	0x1302: {kind: kindGCM, keyLen: 32, block: aes.NewCipher, prfHash: sha512.New384, tls13: true},
	0x1303: {kind: kindChaCha, keyLen: chacha20poly1305.KeySize, prfHash: sha256.New, tls13: true},

	0x009C: gcmSuite(16, sha256.New), 0x009D: gcmSuite(32, sha512.New384),
	0x009E: gcmSuite(16, sha256.New), 0x009F: gcmSuite(32, sha512.New384),
	0xC02B: gcmSuite(16, sha256.New), 0xC02C: gcmSuite(32, sha512.New384),
	0xC02F: gcmSuite(16, sha256.New), 0xC030: gcmSuite(32, sha512.New384),

	0xCCA8: chachaSuite, 0xCCA9: chachaSuite, 0xCCAA: chachaSuite,

	0x002F: cbcSuite(16, aes.NewCipher, sha1.New), 0x0035: cbcSuite(32, aes.NewCipher, sha1.New),
	0x0033: cbcSuite(16, aes.NewCipher, sha1.New), 0x0039: cbcSuite(32, aes.NewCipher, sha1.New),
	0xC009: cbcSuite(16, aes.NewCipher, sha1.New), 0xC00A: cbcSuite(32, aes.NewCipher, sha1.New),
	0xC013: cbcSuite(16, aes.NewCipher, sha1.New), 0xC014: cbcSuite(32, aes.NewCipher, sha1.New),
	0x003C: cbcSuite(16, aes.NewCipher, sha256.New), 0x003D: cbcSuite(32, aes.NewCipher, sha256.New),
	0x0067: cbcSuite(16, aes.NewCipher, sha256.New), 0x006B: cbcSuite(32, aes.NewCipher, sha256.New),
	0xC023: cbcSuite(16, aes.NewCipher, sha256.New), 0xC024: cbcSuite(32, aes.NewCipher, sha512.New384),
	0xC027: cbcSuite(16, aes.NewCipher, sha256.New), 0xC028: cbcSuite(32, aes.NewCipher, sha512.New384),
	0x000A: cbcSuite(24, des.NewTripleDESCipher, sha1.New), 0xC012: cbcSuite(24, des.NewTripleDESCipher, sha1.New),
}

var errBadRecord = errors.New("record failed to decrypt")

// decrypter removes the protection from the records of one direction. It returns the content type of the plaintext,
// which TLS 1.3 hides inside the record.
type decrypter interface {
	decrypt(typ byte, version uint16, payload []byte) (byte, []byte, error)
}

func newAEAD(s *suite, key []byte) (cipher.AEAD, error) {
	if s.kind == kindChaCha {
		return chacha20poly1305.New(key)
	}
	b, err := s.block(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func seqNonce(iv []byte, seq uint64) []byte {
	nonce := append([]byte(nil), iv...)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	for i, b := range s {
		nonce[len(nonce)-8+i] ^= b
	}
	return nonce
}

func aad12(seq uint64, typ byte, version uint16, n int) []byte {
	ad := make([]byte, 13)
	binary.BigEndian.PutUint64(ad, seq)
	ad[8] = typ
	binary.BigEndian.PutUint16(ad[9:], version)
	binary.BigEndian.PutUint16(ad[11:], uint16(n)) //nolint:gosec // a TLS record is at most 2^14 + 2048 bytes
	return ad
}

type aead12 struct {
	aead cipher.AEAD
	iv   []byte
	gcm  bool
	seq  uint64
}

func (d *aead12) decrypt(typ byte, version uint16, payload []byte) (byte, []byte, error) {
	var nonce []byte
	if d.gcm {
		// RFC 5288: the fixed IV, then an 8 byte nonce the record carries in the clear.
		if len(payload) < 8 {
			return 0, nil, errBadRecord
		}
		nonce = append(append([]byte(nil), d.iv...), payload[:8]...)
		payload = payload[8:]
	} else {
		nonce = seqNonce(d.iv, d.seq)
	}
	n := len(payload) - d.aead.Overhead()
	if n < 0 {
		return 0, nil, errBadRecord
	}
	plain, err := d.aead.Open(nil, nonce, payload, aad12(d.seq, typ, version, n))
	d.seq++
	if err != nil {
		return 0, nil, errBadRecord
	}
	return typ, plain, nil
}

type cbc12 struct {
	block  cipher.Block
	mac    hash.Hash
	macLen int
	iv     []byte // TLS 1.0 only: the IV chains from the last ciphertext block
	etm    bool
	seq    uint64
}

func (d *cbc12) checkMAC(typ byte, version uint16, data, tag []byte) error {
	d.mac.Reset()
	d.mac.Write(aad12(d.seq, typ, version, len(data)))
	d.mac.Write(data)
	if !hmac.Equal(d.mac.Sum(nil), tag) {
		return errBadRecord
	}
	return nil
}

func (d *cbc12) decrypt(typ byte, version uint16, payload []byte) (byte, []byte, error) {
	defer func() { d.seq++ }()
	bs := d.block.BlockSize()

	if d.etm {
		// RFC 7366: the MAC covers the IV and the ciphertext, and sits outside the encryption.
		if len(payload) < d.macLen {
			return 0, nil, errBadRecord
		}
		ct, tag := payload[:len(payload)-d.macLen], payload[len(payload)-d.macLen:]
		if err := d.checkMAC(typ, version, ct, tag); err != nil {
			return 0, nil, err
		}
		plain, err := d.cbcOpen(version, ct, bs)
		if err != nil {
			return 0, nil, err
		}
		return typ, plain, nil
	}

	plain, err := d.cbcOpen(version, payload, bs)
	if err != nil {
		return 0, nil, err
	}
	if len(plain) < d.macLen {
		return 0, nil, errBadRecord
	}
	content, tag := plain[:len(plain)-d.macLen], plain[len(plain)-d.macLen:]
	if err := d.checkMAC(typ, version, content, tag); err != nil {
		return 0, nil, err
	}
	return typ, content, nil
}

// cbcOpen decrypts and strips the padding.
func (d *cbc12) cbcOpen(version uint16, ct []byte, bs int) ([]byte, error) {
	iv := d.iv
	if version >= versionTLS11 {
		if len(ct) < bs {
			return nil, errBadRecord
		}
		iv, ct = ct[:bs], ct[bs:]
	}
	if len(ct) == 0 || len(ct)%bs != 0 {
		return nil, errBadRecord
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(d.block, iv).CryptBlocks(plain, ct)
	if version < versionTLS11 {
		d.iv = append([]byte(nil), ct[len(ct)-bs:]...)
	}
	pad := int(plain[len(plain)-1]) + 1
	if pad > len(plain) {
		return nil, errBadRecord
	}
	return plain[:len(plain)-pad], nil
}

type aead13 struct {
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
	secret []byte // set for an application traffic secret, which a KeyUpdate derives the next one from
}

func newAEAD13(s *suite, secret []byte) (*aead13, error) {
	key := hkdfExpandLabel(s.prfHash, secret, "key", s.keyLen)
	a, err := newAEAD(s, key)
	if err != nil {
		return nil, err
	}
	return &aead13{aead: a, iv: hkdfExpandLabel(s.prfHash, secret, "iv", 12)}, nil
}

func (d *aead13) decrypt(typ byte, version uint16, payload []byte) (byte, []byte, error) {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint16(hdr[1:], version)
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(payload))) //nolint:gosec // the pump drops records over maxRecordLen
	plain, err := d.aead.Open(nil, seqNonce(d.iv, d.seq), payload, hdr)
	d.seq++
	if err != nil {
		return 0, nil, errBadRecord
	}
	// RFC 8446 section 5.4: the real content type is the last non-zero byte.
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, errBadRecord
	}
	return plain[i], plain[:i], nil
}

// keys12 derives the client and server decrypters of a TLS 1.0 to 1.2 connection from its master secret.
func keys12(s *suite, version uint16, master []byte, cr, sr random, etm bool) (decrypter, decrypter, error) {
	ivLen := s.fixedIVLen()
	macLen := s.macLen()
	n := 2*macLen + 2*s.keyLen + 2*ivLen
	seed := make([]byte, 0, 2*len(random{}))
	seed = append(append(seed, sr[:]...), cr[:]...)
	var kb []byte
	if version >= versionTLS12 {
		kb = prf12(s.prfHash, master, "key expansion", seed, n)
	} else {
		kb = prf10(master, "key expansion", seed, n)
	}
	take := func(l int) []byte {
		out := kb[:l]
		kb = kb[l:]
		return out
	}
	cMAC, sMAC := take(macLen), take(macLen)
	cKey, sKey := take(s.keyLen), take(s.keyLen)
	cIV, sIV := take(ivLen), take(ivLen)

	build := func(mac, key, iv []byte) (decrypter, error) {
		if s.kind == kindCBC {
			b, err := s.block(key)
			if err != nil {
				return nil, err
			}
			return &cbc12{block: b, mac: hmac.New(s.macHash, mac), macLen: macLen, iv: iv, etm: etm}, nil
		}
		a, err := newAEAD(s, key)
		if err != nil {
			return nil, err
		}
		return &aead12{aead: a, iv: iv, gcm: s.kind == kindGCM}, nil
	}
	c, err := build(cMAC, cKey, cIV)
	if err != nil {
		return nil, nil, fmt.Errorf("client keys: err=%w", err)
	}
	sv, err := build(sMAC, sKey, sIV)
	if err != nil {
		return nil, nil, fmt.Errorf("server keys: err=%w", err)
	}
	return c, sv, nil
}
