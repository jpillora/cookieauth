package cookieauth

import (
	"crypto/subtle"
	"errors"
	"fmt"

	scrypt "github.com/elithrar/simple-scrypt"
	"github.com/gofrs/uuid"
	lru "github.com/hashicorp/golang-lru"
)

type Authenticator interface {
	WithCreds(user, pass string) (bool, []byte, error)
	WithCookie(b64 []byte) (bool, error)
}

type UserAuth struct {
	user  string
	pass  string
	cache *lru.Cache
}

func NewUserAuth(user, pass string) *UserAuth {
	l, err := lru.New(cacheSize)
	if err != nil {
		panic("error in cache creation")
	}
	return &UserAuth{user: user, pass: pass, cache: l}
}

func (sa *UserAuth) WithCreds(user, pass string) (bool, []byte, error) {
	up := concat(sa.user, sa.pass)
	if subtle.ConstantTimeCompare(up, concat(user, pass)) != 1 {
		return false, nil, nil
	}
	//cached token?
	if hash, ok := sa.cache.Get(string(up)); ok {
		return true, hash.([]byte), nil
	}

	//generate password hash
	hash, err := scrypt.GenerateFromPassword(up, params)
	if err != nil {
		return false, nil, errors.New("hash failed")
	}

	sa.cache.Add(string(up), hash)

	return true, hash, nil
}

func (sa *UserAuth) WithCookie(hash []byte) (bool, error) {
	//check password hash
	fmt.Println("generating")
	err := scrypt.CompareHashAndPassword(hash, concat(sa.user, sa.pass))
	if err == nil {
		return true, nil
	}
	return false, err
}

type UsersAuth struct {
	users    map[string]string
	sessions map[string]string
}

func NewUsersAuth(users map[string]string) *UsersAuth {

	return &UsersAuth{users: users, sessions: make(map[string]string)}
}

func (ua *UsersAuth) WithCreds(user, pass string) (bool, []byte, error) {

	p, ok := ua.users[user]
	if !ok {
		return false, nil, nil
	}
	if subtle.ConstantTimeCompare(concat(user, p), concat(user, pass)) == 1 {
		id, err := uuid.NewV4()
		if err != nil {
			return false, nil, err
		}
		ua.sessions[id.String()] = user
		return true, id.Bytes(), nil
	}
	return false, nil, nil
}

func (ua *UsersAuth) WithCookie(hash []byte) (bool, error) {

	//just check if the session is in the sessions list
	sID, err := uuid.FromBytes(hash)
	if err != nil {
		return false, err
	}
	_, ok := ua.sessions[sID.String()]
	if ok {
		return true, nil
	}

	return false, nil
}
