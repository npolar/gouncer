package gouncer

import (
	"encoding/json"
	"github.com/bradfitz/gomemcache/memcache"
	"io/ioutil"
	"net/http"
)

type Authenticator struct {
	Credentials
	Cache   []string
	GroupDB string
	UserDB  string
	ResponseHandler
}

func NewAuthenticator(w http.ResponseWriter, r *http.Request) *Authenticator {
	a := &Authenticator{}
	a.Writer = w
	a.HttpRequest = r
	a.Response = &AuthResponse{}

	return a
}

func (auth *Authenticator) HandleTokenRequest() {
	if err := auth.ParseAuthHeader(auth.HttpRequest.Header.Get("Authorization")); err == nil {
		auth.GenerateToken()
	} else {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}

	auth.Respond()
}

func (auth *Authenticator) GenerateToken() {
	if tokenizer, err := NewTokenizer(auth.Password, auth.FetchUser()); err == nil {
		tokenizer.GroupDB = auth.GroupDB
		token, err := tokenizer.GenerateJWT()

		if err != nil {
			auth.NewError(http.StatusUnauthorized, err.Error())
		}

		if err = auth.CacheTokenInfo(tokenizer.Secret); err == nil {
			auth.Response.Token = token
		} else {
			auth.NewError(http.StatusInternalServerError, err.Error())
		}
	} else {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

// CacheTokenInfo caches the username and secret for validation purposes
func (auth *Authenticator) CacheTokenInfo(secret string) error {
	mc := memcache.New(auth.Cache...)
	return mc.Set(&memcache.Item{Key: auth.Username, Value: []byte(secret), Expiration: 1200})
}

func (auth *Authenticator) FetchUser() map[string]interface{} {
	var caller = make(map[string]interface{})

	if response, err := http.Get(auth.UserDB + "/" + auth.Username); err == nil {
		user, _ := ioutil.ReadAll(response.Body)
		defer response.Body.Close()

		if err = json.Unmarshal(user, &caller); err != nil {
			auth.NewError(http.StatusInternalServerError, "Error retrieving user info")
		}
	} else {
		auth.NewError(http.StatusInternalServerError, "Error retrieving user info")
	}

	return caller
}
