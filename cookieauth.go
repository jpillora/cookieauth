package cookieauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"time"
)

const (
	pkgID     = "cookieauth"
	saltLen   = 32
	hashLen   = 32
	day       = 24 * time.Hour
	fortnight = 14 * day
)

type Options struct {
	User   string
	Pass   string
	Expiry time.Duration
	Log    bool
}

func WrapOptions(next http.Handler, opts Options) http.Handler {
	return &cookieauth{
		Options:  opts,
		expected: []byte(opts.User + ":" + opts.Pass),
		next:     next,
	}
}

func Wrap(next http.Handler, user, pass string) http.Handler {
	return WrapOptions(next, Options{
		User:   user,
		Pass:   pass,
		Expiry: fortnight,
	})
}

type cookieauth struct {
	Options
	expected []byte
	next     http.Handler
}

func (ca *cookieauth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//login with creds
	if u, p, ok := r.BasicAuth(); ok {
		b64, err := ca.authWithCreds(u, p)
		if err != nil {
			if ca.Log {
				log.Printf("cookieauth login error: %s", err)
			}
			ca.authFailed(w)
			return
		}
		//set cookie
		http.SetCookie(w, &http.Cookie{
			Name:    pkgID,
			Value:   b64,
			Expires: time.Now().Add(ca.Expiry),
		})
		ca.next.ServeHTTP(w, r)
		return
	}
	//login with token
	for _, c := range r.Cookies() {
		if c.Name == pkgID {
			b64 := c.Value
			if err := ca.authWithToken(b64); err != nil {
				if ca.Log {
					log.Printf("cookieauth token error:  %s", err)
				}
				ca.authFailed(w)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:    pkgID,
				Value:   b64,
				Expires: time.Now().Add(ca.Expiry),
			})
			ca.next.ServeHTTP(w, r)
			return
		}
	}
	//no auth detected!
	ca.authFailed(w)
}

func (ca *cookieauth) authFailed(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   pkgID,
		MaxAge: -1,
	})
	w.Header().Set("WWW-Authenticate", "Basic")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func (ca *cookieauth) authWithCreds(user, pass string) (string, error) {
	attempt := []byte(user + ":" + pass)
	//check password
	if subtle.ConstantTimeCompare(ca.expected, attempt) != 1 {
		return "", errors.New("incorrect password")
	}
	//create random salt
	salt := make([]byte, saltLen)
	n, _ := rand.Read(salt)
	if n != saltLen {
		return "", errors.New("rand failed")
	}
	//hmac password
	m := hmac.New(sha256.New, ca.expected)
	m.Write(salt)
	hash := m.Sum(nil)
	//concat, encode base64
	return base64.StdEncoding.EncodeToString(append(salt, hash...)), nil
}

func (ca *cookieauth) authWithToken(b64 string) error {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	if len(b) != saltLen+hashLen {
		return errors.New("invalid token length")
	}
	userSalt := b[0:saltLen]
	userHash := b[saltLen:]
	//hmac password with user salt
	m := hmac.New(sha256.New, ca.expected)
	m.Write(userSalt)
	expectedHash := m.Sum(nil)
	//ensure match
	if !hmac.Equal(userHash, expectedHash) {
		return errors.New("invalid hash")
	}
	return nil
}
