package cookieauth

import (
	"testing"

	scrypt "github.com/elithrar/simple-scrypt"
)

func TestUserAuth(t *testing.T) {
	auth := NewUserAuth("foo", "bar")

	ok, _, _ := auth.WithCreds("baz", "bar")
	if ok {
		t.Error("expected false, got true")
	}

	ok, _, _ = auth.WithCreds("foo", "bar")
	if !ok {
		t.Error("expected true, got false")
	}

	hash, _ := scrypt.GenerateFromPassword([]byte("baz:bar"), params)
	ok, err := auth.WithCookie(hash)
	if err == nil {
		t.Error("expected false, got true")
	}

	hash, _ = scrypt.GenerateFromPassword([]byte("foo:bar"), params)
	ok, err = auth.WithCookie(hash)
	if err != nil {
		t.Error("expected true, got false")
	}

}

func TestUsersAuth(t *testing.T) {
	users := map[string]string{
		"foo": "bar",
		"baz": "bar",
	}

	auth := NewUsersAuth(users)
	ok, passphrase0, _ := auth.WithCreds("zip", "zop")
	if passphrase0 != nil {
		t.Error("passphhrase should be nil")
	}
	if ok {
		t.Error("expected false, got true")
	}

	ok, passphrase1, _ := auth.WithCreds("foo", "bar")
	if !ok {
		t.Error("expected true, got false")
	}

	ok, _, _ = auth.WithCreds("baz", "bar")
	if !ok {
		t.Error("expected true, got false")
	}

	ok, err := auth.WithCookie(passphrase1)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("expected true, got false")
	}

	ok, err = auth.WithCookie(nil)
	if err == nil {
		t.Error(err)
	}
	if ok {
		t.Error("expected false, got true")
	}

}
