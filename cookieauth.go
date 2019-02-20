package cookieauth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	scrypt "github.com/elithrar/simple-scrypt"
	lru "github.com/hashicorp/golang-lru"
)

const (
	cacheSize      = 1024
	fortnight      = 14 * 24 * time.Hour
	setCookieAfter = 24 * time.Hour
)

var params = scrypt.Params{N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32}

func New() *CookieAuth {
	l, _ := lru.New(cacheSize)
	ca := &CookieAuth{
		id:     "cookieauth",
		expiry: fortnight,
		path:   "/",
		auth:   nil,
		realm:  "",
		logger: nil,
		cache:  l,
		next:   nil,
	}
	return ca
}

//AuthFunc accepts user and password and provides a boolean value if the user/pasoword combination is valid,
//a slice of bytes which contains an identifier of the user (a concatenation of user and password is an example) and an error
type AuthFunc func(user string, password string) (bool, []byte, error)

func NewSimpleAuthFunc(username, password string) AuthFunc {
	auth := concat(username, password)
	return func(user, pass string) (bool, []byte, error) {
		if subtle.ConstantTimeCompare(auth, concat(user, pass)) == 1 {
			return true, auth, nil
		}

		return false, nil, nil
	}
}

func NewAuthFuncFromMap(users map[string]string) AuthFunc {

	return func(user, pass string) (bool, []byte, error) {
		if users[user] != "" {
			auth := concat(user, users[user])
			if subtle.ConstantTimeCompare(auth, concat(user, pass)) == 1 {
				return true, auth, nil
			}
		}

		return false, nil, nil
	}
}

//CookieAuth implements the a cookie based HTTP basic auth middleware
type CookieAuth struct {
	mut      sync.RWMutex
	id       string
	auth     []byte
	authFunc AuthFunc
	realm    string
	expiry   time.Duration
	path     string
	logger   *log.Logger
	cache    *lru.Cache
	next     http.Handler
}

//Wrap the provided handler with basic auth
func Wrap(next http.Handler, user, pass string) http.Handler {
	ca := New()
	ca.SetUserPass(user, pass)
	return ca.Wrap(next)
}

//WrapWithRealm the provided handler with basic auth in the given realm
func WrapWithRealm(next http.Handler, user, pass, realm string) http.Handler {
	ca := New()
	ca.SetUserPass(user, pass)
	ca.SetRealm(realm)
	return ca.Wrap(next)
}

//WrapWithFunc the provider handler with basic auth using the AuthFunc provided
func WrapWithFunc(next http.Handler, authFunc AuthFunc, realm string) http.Handler {
	ca := New()
	ca.SetAuthFunc(authFunc)
	ca.SetRealm(realm)
	return ca.Wrap(next)
}

func (ca *CookieAuth) Wrap(next http.Handler) http.Handler {
	ca.SetNextHandler(next)
	return ca
}

//SetNextHandler sets the next http.Handler to use in
//this middle chain
func (ca *CookieAuth) SetNextHandler(next http.Handler) *CookieAuth {
	ca.mut.Lock()
	ca.next = next
	ca.mut.Unlock()
	return ca
}

//SetUserPass sets the current username and password
func (ca *CookieAuth) SetUserPass(user, pass string) *CookieAuth {
	ca.mut.Lock()
	if user == "" && pass == "" {
		ca.authFunc = nil
	} else {
		ca.authFunc = NewSimpleAuthFunc(user, pass)
	}
	ca.auth = nil
	ca.cache.Purge()
	ca.mut.Unlock()
	return ca
}

//SetAuthFunc sets the current authFunc
func (ca *CookieAuth) SetAuthFunc(f AuthFunc) *CookieAuth {
	ca.mut.Lock()
	ca.authFunc = f
	ca.auth = nil
	ca.cache.Purge()
	ca.mut.Unlock()
	return ca
}

//SetRealm sets the realm for the authentication response (default: "")
func (ca *CookieAuth) SetRealm(realm string) *CookieAuth {
	ca.mut.Lock()
	ca.realm = strings.Replace(realm, `"`, ``, -1)
	ca.cache.Purge()
	ca.mut.Unlock()
	return ca
}

//SetExpiry defines the cookie expiration time
func (ca *CookieAuth) SetExpiry(expiry time.Duration) *CookieAuth {
	ca.mut.Lock()
	ca.expiry = expiry
	ca.mut.Unlock()
	return ca
}

//SetPath defines the cookie path. Set to
//the empty string to use the request path.
func (ca *CookieAuth) SetPath(path string) *CookieAuth {
	ca.mut.Lock()
	ca.path = path
	ca.mut.Unlock()
	return ca
}

//SetLogger sets the log.Logger used to
//display actions
func (ca *CookieAuth) SetLogger(l *log.Logger) *CookieAuth {
	ca.mut.Lock()
	ca.logger = l
	ca.mut.Unlock()
	return ca
}

//SetID changes the cookie ID, defaults
//to "cookieauth"
func (ca *CookieAuth) SetID(id string) *CookieAuth {
	ca.mut.Lock()
	ca.id = id
	ca.mut.Unlock()
	return ca
}

func (ca *CookieAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ca.mut.RLock()
	caid := ca.id
	ca.mut.RUnlock()
	//no authFunc, so no credentials
	if ca.authFunc == nil {
		ca.next.ServeHTTP(w, r)
		return
	}
	//login with token
	for _, c := range r.Cookies() {
		if c.Name == caid {
			c2, err := ca.authWithCookie(c)
			if err != nil {
				ca.logf("token error:  %s", err)
				ca.authFailed(w)
				return
			}
			if c2 == nil {
				ca.logf("token success (keep cookie)")
			} else {
				//set a new cookie
				http.SetCookie(w, c2)
				ca.logf("token success (new cookie)")
			}
			ca.next.ServeHTTP(w, r)
			return
		}
	}
	//login with creds
	if u, p, ok := r.BasicAuth(); ok {
		b64, err := ca.authWithCreds(u, p)
		if err != nil {
			ca.logf("basic-auth error: %s", err)
			ca.authFailed(w)
			return
		}
		//load expiry
		ca.mut.RLock()
		expires := time.Now().Add(ca.expiry)
		ca.mut.RUnlock()
		//set cookie
		http.SetCookie(w, ca.generateCookie(b64, expires))
		ca.logf("basic-auth success")
		ca.next.ServeHTTP(w, r)
		return
	}
	//no auth detected!
	ca.logf("not authenticated")
	ca.authFailed(w)
}

func (ca *CookieAuth) getAuth() []byte {
	ca.mut.RLock()
	b := make([]byte, len(ca.auth))
	copy(b, ca.auth)
	ca.mut.RUnlock()
	return b
}

func (ca *CookieAuth) setAuth(auth []byte) *CookieAuth {
	//In principle we have no need of purging cache
	//since having other cached users may be useful
	ca.mut.Lock()
	ca.auth = auth
	//ca.cache.Purge()
	ca.mut.Unlock()
	return ca
}

func (ca *CookieAuth) generateCookie(b64 string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:    ca.id,
		Value:   b64 + "|" + strconv.FormatInt(expires.Unix(), 10),
		Path:    ca.path,
		Expires: expires,
	}
}

func (ca *CookieAuth) authFailed(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: ca.id, MaxAge: -1})
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, ca.realm))
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func (ca *CookieAuth) authWithCreds(user, pass string) (string, error) {

	if ca.authFunc == nil {
		return "", errors.New("authFunc is nil")
	}

	//check password
	ok, auth, err := ca.authFunc(user, pass)
	if err != nil {
		return "", errors.New("authFunc error")
	}

	if !ok {
		return "", errors.New("incorrect user/password")
	}

	ca.setAuth(auth)

	//cached token?
	if b64, ok := ca.cache.Get(string(ca.getAuth())); ok {
		return b64.(string), nil
	}
	//generate password hash
	hash, err := scrypt.GenerateFromPassword(ca.getAuth(), params)
	if err != nil {
		return "", errors.New("hash failed")
	}
	//encode base64
	b64 := base64.StdEncoding.EncodeToString(hash)
	ca.cache.Add(string(ca.getAuth()), b64)
	return b64, nil
}

func (ca *CookieAuth) authWithCookie(c *http.Cookie) (*http.Cookie, error) {
	b64 := c.Value
	//optionally extract an epoch integer from the end
	epoch := int64(0)
	if pair := strings.SplitN(b64, "|", 2); len(pair) == 2 {
		if i, err := strconv.ParseInt(pair[1], 10, 64); err == nil {
			epoch = i
			b64 = pair[0]
		}
	}
	//load expiry
	ca.mut.RLock()
	expires := time.Now().Add(ca.expiry)
	ca.mut.RUnlock()
	//new cookie? set when cookie's expiry
	//the passes the preset threshold
	var c2 *http.Cookie
	if epoch == 0 || expires.Sub(time.Unix(epoch, 0)) > setCookieAfter {
		c2 = ca.generateCookie(b64, expires)
	}
	//cached token?
	if ca.cache.Contains(b64) {
		return c2, nil
	}
	//decode base64
	hash, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("b64 error")
	}
	//check password hash
	if err := scrypt.CompareHashAndPassword(hash, ca.getAuth()); err != nil {
		return nil, err
	}
	//cache result!
	ca.cache.Add(b64, true)
	//success
	return c2, nil
}

func (ca *CookieAuth) logf(format string, args ...interface{}) {
	ca.mut.RLock()
	l := ca.logger
	ca.mut.RUnlock()
	if l != nil {
		l.Printf("[cookieauth] "+format, args...)
	}
}

func concat(u, p string) []byte {
	return []byte(u + ":" + p)
}
