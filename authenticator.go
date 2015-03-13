package gouncer

import (
	"github.com/RDux/toki"
	"github.com/bradfitz/gomemcache/memcache"
	"log"
	"net/http"
)

type Authenticator struct {
	Credentials
	Backend    *Backend
	Expiration int32 // Token expiration time
	TokenAlg   string
	*ResponseHandler
}

func NewAuthenticator(h *ResponseHandler) *Authenticator {
	a := &Authenticator{}
	a.ResponseHandler = h

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
	userInfo, err := auth.FetchUser()

	if err == nil {
		auth.ResolveHashAlg(userInfo["hash"].(string))

		// Check if the provided password matches that in the user database
		if userInfo["password"].(string) == auth.PasswordHash() {
			auth.GenerateSecret()
			tokenizer := toki.NewJsonWebToken()
			tokenizer.TokenAlgorithm = auth.ResolveTokenAlgorithm()

			// Set the token contents
			tokenizer.Claim.Content = auth.TokenBody(userInfo)

			// Sign the token and return the full token string
			tokenizer.Sign(auth.Secret)
			token, err := tokenizer.String()

			if err == nil {
				// Cache the token info for validation purposes
				err = auth.CacheTokenInfo(auth.Secret)

				// When token info is cached respond with the token
				if err == nil {
					auth.Response.Token = token
				}
			}

			if err != nil {
				auth.NewError(http.StatusUnauthorized, err.Error())
			}
		}
	} else {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (auth *Authenticator) ResolveTokenAlgorithm() *toki.Algorithm {
	switch auth.TokenAlg {
	case "HS384":
		return toki.HS384()
	case "HS512":
		return toki.HS512()
	default:
		return toki.HS256()
	}
}

// CacheTokenInfo caches the username and secret for validation purposes
func (auth *Authenticator) CacheTokenInfo(secret string) error {
	return auth.Backend.Cache.Set(&memcache.Item{Key: auth.Username, Value: []byte(secret), Expiration: auth.Expiration})
}

// Generate the contents that will be sent in the tokens claim body
func (auth *Authenticator) TokenBody(userData map[string]interface{}) map[string]interface{} {
	var content = make(map[string]interface{})
	var systems = make(map[string]interface{})

	content["user"] = auth.Username

	if uri, exists := userData["uri"]; exists {
		content["uri"] = uri
	}

	if groups, exists := userData["groups"]; exists {
		systems = auth.ResolveGroupsToSystems(groups.([]interface{}))
	}

	if list, exists := userData["systems"].(map[string]interface{}); exists {
		for system, rights := range list {
			systems[system] = rights
		}
	}

	if len(systems) > 0 {
		content["systems"] = systems
	}

	return content
}

func (auth *Authenticator) FetchUser() (map[string]interface{}, error) {
	couch := NewCouch(auth.Backend.Server, auth.Backend.UserDB)
	return couch.Get(auth.Username)
}

func (auth *Authenticator) ResolveGroupsToSystems(groups []interface{}) map[string]interface{} {
	couch := NewCouch(auth.Backend.Server, auth.Backend.GroupDB)
	docs, err := couch.GetMultiple(groups)

	if err != nil {
		log.Println("Error resolving groups: ", err)
	}

	var systems = make(map[string]interface{})

	if err == nil {
		for _, doc := range docs {
			if systemList, exists := doc.(map[string]interface{})["systems"]; exists {
				for system, rights := range systemList.(map[string]interface{}) {
					systems[system] = rights
				}
			}
		}
	}

	return systems
}
