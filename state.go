package oidcrp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// loginState is the data bound to the browser in the signed state cookie.
type loginState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x,omitempty"`
	Expires  int64  `json:"e"`
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (rp *RP) sign(payload string) string {
	m := hmac.New(sha256.New, rp.cfg.CookieSecret)
	m.Write([]byte("oidcrp.state.v1."))
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (rp *RP) seal(s loginState) string {
	j, _ := json.Marshal(s)
	p := base64.RawURLEncoding.EncodeToString(j)
	return p + "." + rp.sign(p)
}

// open verifies signature and expiry and decodes the cookie value.
func (rp *RP) open(v string) (loginState, error) {
	var s loginState
	p, sig, ok := strings.Cut(v, ".")
	if !ok || p == "" || sig == "" {
		return s, ErrStateInvalid
	}
	if subtle.ConstantTimeCompare([]byte(sig), []byte(rp.sign(p))) != 1 {
		return s, ErrStateInvalid
	}
	j, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || json.Unmarshal(j, &s) != nil {
		return s, ErrStateInvalid
	}
	if time.Now().Unix() > s.Expires {
		return s, ErrStateExpired
	}
	return s, nil
}

// safeNext returns next only when it is a same-origin relative path.
func safeNext(next string) string {
	if next == "" || next[0] != '/' || strings.HasPrefix(next, "//") {
		return ""
	}
	for _, r := range next {
		if r == '\\' || r < 0x20 || r == 0x7f {
			return ""
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return ""
	}
	return next
}
