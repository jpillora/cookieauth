package cookieauth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	scrypt "github.com/elithrar/simple-scrypt"
)

const (
	pkgID = "cookieauth"
	// cacheSize = 128
	fortnight = 14 * 24 * time.Hour
)

var params = scrypt.Params{N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32}

func New() *CookieAuth {
	ca := &CookieAuth{
		expiry: fortnight,
		auth:   nil,
		logger: nil,
		next:   nil,
	}
	return ca
}

type CookieAuth struct {
	mut    sync.RWMutex
	auth   []byte
	expiry time.Duration
	logger *log.Logger
	next   http.Handler
}

func Wrap(next http.Handler, user, pass string) http.Handler {
	ca := New()
	ca.SetUserPass(user, pass)
	return ca.Wrap(next)
}

func (ca *CookieAuth) Wrap(next http.Handler) http.Handler {
	return ca.SetNextHandler(next)
}

func (ca *CookieAuth) SetNextHandler(next http.Handler) http.Handler {
	ca.mut.Lock()
	ca.next = next
	ca.mut.Unlock()
	return ca
}

func (ca *CookieAuth) SetUserPass(user, pass string) {
	ca.mut.Lock()
	if user == "" && pass == "" {
		ca.auth = nil
	} else {
		ca.auth = concat(user, pass)
	}
	ca.mut.Unlock()
}

func (ca *CookieAuth) SetExpiry(expiry time.Duration) {
	ca.mut.Lock()
	ca.expiry = expiry
	ca.mut.Unlock()
}

func (ca *CookieAuth) SetLogger(l *log.Logger) {
	if l.Prefix() == "" {
		l.SetPrefix("[" + pkgID + "] ")
	}
	ca.mut.Lock()
	ca.logger = l
	ca.mut.Unlock()
}

func (ca *CookieAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//no creds
	if len(ca.getAuth()) == 0 {
		ca.next.ServeHTTP(w, r)
		return
	}
	//login with creds
	if u, p, ok := r.BasicAuth(); ok {
		b64, err := ca.authWithCreds(u, p)
		if err != nil {
			ca.logf("login error: %s", err)
			ca.authFailed(w)
			return
		}
		//set cookie
		http.SetCookie(w, &http.Cookie{
			Name:    pkgID,
			Value:   b64,
			Expires: time.Now().Add(ca.expiry),
		})
		ca.logf("login success")
		ca.next.ServeHTTP(w, r)
		return
	}
	//login with token
	for _, c := range r.Cookies() {
		if c.Name == pkgID {
			b64 := c.Value
			if err := ca.authWithToken(b64); err != nil {
				ca.logf("token error:  %s", err)
				ca.authFailed(w)
				return
			}
			ca.mut.RLock()
			expires := time.Now().Add(ca.expiry)
			ca.mut.RUnlock()
			http.SetCookie(w, &http.Cookie{
				Name:    pkgID,
				Value:   b64,
				Expires: expires,
			})
			ca.logf("token success")
			ca.next.ServeHTTP(w, r)
			return
		}
	}
	//no auth detected!
	ca.logf("not authenticated")
	ca.authFailed(w)
}

func (ca *CookieAuth) getAuth() []byte {
	b := make([]byte, len(ca.auth))
	ca.mut.RLock()
	copy(b, ca.auth)
	ca.mut.RUnlock()
	return b
}

func (ca *CookieAuth) authFailed(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: pkgID, MaxAge: -1})
	w.Header().Set("WWW-Authenticate", "Basic")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func (ca *CookieAuth) authWithCreds(user, pass string) (string, error) {
	//check password
	if subtle.ConstantTimeCompare(ca.auth, concat(user, pass)) != 1 {
		return "", errors.New("incorrect password")
	}
	//generate password hash
	hash, err := scrypt.GenerateFromPassword(ca.getAuth(), params)
	if err != nil {
		return "", errors.New("hash failed")
	}
	//encode base64
	return base64.StdEncoding.EncodeToString(hash), nil
}

func (ca *CookieAuth) authWithToken(b64 string) error {
	//decode base64
	hash, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return errors.New("b64 error")
	}
	//check password hash
	if err := scrypt.CompareHashAndPassword(hash, ca.getAuth()); err != nil {
		return err
	}
	return nil
}

func (ca *CookieAuth) logf(format string, args ...interface{}) {
	if ca.logger != nil {
		ca.logger.Printf(format, args...)
	}
}

func concat(u, p string) []byte {
	return []byte(u + ":" + p)
}
