package cookieauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gavv/httpexpect"
)

func TestNewSimpleAuthFunc(t *testing.T) {
	f := NewSimpleAuthFunc("foo", "bar")
	ok, auth, _ := f("baz", "bar")
	if string(auth) != "foo:bar" {
		t.Errorf("auth is not correct: %v", string(auth))
	}
	if ok {
		t.Error("expected false, got true")
	}

	ok, auth, _ = f("foo", "bar")
	if string(auth) != "foo:bar" {
		t.Errorf("auth is not correct: %v", string(auth))
	}
	if !ok {
		t.Error("expected true, got false")
	}

}

func TestNewAuthFuncFromMap(t *testing.T) {
	users := map[string]string{
		"foo": "bar",
		"baz": "bar",
	}

	f := NewAuthFuncFromMap(users)
	ok, auth, _ := f("zip", "zop")
	if auth != nil {
		t.Errorf("auth is not correct: %v", string(auth))
	}
	if ok {
		t.Error("expected false, got true")
	}

	ok, auth, _ = f("foo", "bar")
	if string(auth) != "foo:bar" {
		t.Errorf("auth is not correct: %v", string(auth))
	}
	if !ok {
		t.Error("expected true, got false")
	}

	ok, auth, _ = f("baz", "bar")
	if string(auth) != "baz:bar" {
		t.Errorf("auth is not correct: %v", string(auth))
	}
	if !ok {
		t.Error("expected true, got false")
	}

}

func TestAll(t *testing.T) {
	//secret handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`hello world`))
	})
	token := "session"
	//protect with cookieauth
	ca := New()
	ca.SetID(token)
	ca.SetUserPass("foo", "bar")
	//ca.SetLogger(log.New(os.Stdout, "", log.LstdFlags))
	protected := ca.Wrap(handler)
	//start server
	server := httptest.NewServer(protected)
	defer server.Close()
	//example cookie without an expiry
	legacyCookie := "MTYzODQkOCQxJDdmODJiZDc0YjBjNmYxZGVkMGFiMWYyMDQ4ZjRjN2ZhJDg4OTFkZTBkZmJkNTY0ZTU5ZGI0ZmIwZDYwNWE2NWIwNWE3MmM3YTJhNTk3OWM5Mzc2YTc5ZWJlZWZhNjE2NTk="
	//begin
	e := httpexpect.New(t, server.URL)
	e.GET("/").
		Expect().Status(http.StatusUnauthorized)
	e.GET("/").WithBasicAuth("bazz", "bar").
		Expect().Status(http.StatusUnauthorized)
	c := e.GET("/").WithBasicAuth("foo", "bar").
		Expect().Status(http.StatusOK).Cookie(token)
	e.GET("/").WithCookie(token, "incorrect").
		Expect().Status(http.StatusUnauthorized).
		Header("Set-Cookie").Equal("session=; Max-Age=0")
	e.GET("/").WithCookie(token, c.Value().Raw()).
		Expect().Status(http.StatusOK).
		Header("Set-Cookie").Empty()
	e.GET("/").WithCookie(token, legacyCookie).
		Expect().Status(http.StatusOK).
		Header("Set-Cookie").NotEmpty() //legacy tokens have no expiry and so a new cookie must be set
	ca.SetUserPass("zip", "zop")
	e.GET("/").WithCookie(token, c.Value().Raw()).
		Expect().Status(http.StatusUnauthorized)
	c = e.GET("/").WithBasicAuth("zip", "zop").
		Expect().Status(http.StatusOK).Cookie(token)
	e.GET("/").WithCookie(token, c.Value().Raw()).
		Expect().Status(http.StatusOK)
}
