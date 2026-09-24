package tlsdec

import (
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // the TLS 1.0 and 1.1 PRF is defined on MD5
	"crypto/sha1" //nolint:gosec // the TLS 1.0 and 1.1 PRF is defined on SHA-1
	"hash"
)

func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n)
	mac := hmac.New(h, secret)
	mac.Write(seed)
	a := mac.Sum(nil)
	for len(out) < n {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		out = mac.Sum(out)
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return out[:n]
}

// prf12 is the TLS 1.2 PRF of RFC 5246 section 5.
func prf12(h func() hash.Hash, secret []byte, label string, seed []byte, n int) []byte {
	return pHash(h, secret, append([]byte(label), seed...), n)
}

// prf10 is the TLS 1.0 and 1.1 PRF of RFC 2246 section 5: the XOR of an MD5 and a SHA-1 P_hash.
func prf10(secret []byte, label string, seed []byte, n int) []byte {
	ls := append([]byte(label), seed...)
	half := (len(secret) + 1) / 2
	a := pHash(md5.New, secret[:half], ls, n)
	b := pHash(sha1.New, secret[len(secret)-half:], ls, n)
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}

// hkdfExpandLabel is HKDF-Expand-Label of RFC 8446 section 7.1, with an empty context.
func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(n>>8), byte(n), byte(len(full))) //nolint:gosec // TLS asks for at most 64 bytes
	info = append(info, full...)
	info = append(info, 0)

	out := make([]byte, 0, n)
	var prev []byte
	mac := hmac.New(h, secret)
	for i := byte(1); len(out) < n; i++ {
		mac.Reset()
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}
