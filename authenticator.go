package gouncer

import (
	"encoding/json"
	"github.com/npolar/toki"
	"net/http"
	"time"
)

type Authenticator struct {
	Credentials
	*Token
	*ResponseHandler
}

func NewAuthenticator(h *ResponseHandler) *Authenticator {
	return &Authenticator{ResponseHandler: h}
}

// HandleTokenRequest does a header check. If authorization is present it will call
// ProcessTokenRequest to handle futher validation. If no authorization header is present
// it will respond with an unauthorized error
func (auth *Authenticator) HandleTokenRequest() {
	if err := auth.ParseAuthHeader(auth.HttpRequest.Header.Get("Authorization")); err == nil {
		auth.ProcessTokenRequest()
	} else {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

// ProcessTokenRequest retrieves the requested user and checks if the credentials match. If everything
// checks out it calls the TokenResponse to generate the actual response
func (auth *Authenticator) ProcessTokenRequest() {
	valid, err := auth.ValidCredentials()

	if valid {
		auth.TokenResponse(auth.UserInfo)
	}

	if err != nil {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

// TokenResponse uses the toki JWT generator library to create a new JWT.
// The resulting JWT is then set as the resonse token
func (auth *Authenticator) TokenResponse(userInfo map[string]interface{}) {
	auth.GenerateSecret()
	tokenizer := toki.NewJsonWebToken()
	tokenizer.TokenAlgorithm = auth.ResolveAlgorithm()

	// Set the token contents
	tokenizer.Claim.Content = auth.TokenBody(userInfo)

	// Sign the token and return the full token string
	tokenizer.Sign(auth.Secret)
	token, err := tokenizer.String()

	if err == nil {
		// Cache the token info for validation purposes
		err = auth.CacheTokenInfo()

		// When token info is cached respond with the token
		if err == nil {
			auth.Response.Token = token
		}
	}

	if err != nil {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (auth *Authenticator) ResolveAlgorithm() *toki.Algorithm {
	switch auth.Algorithm {
	case "none":
		return toki.NoAlg()
	case "HS384":
		return toki.HS384()
	case "HS512":
		return toki.HS512()
	default:
		return toki.HS256()
	}
}

// CacheTokenInfo caches the username and secret for validation purposes
func (auth *Authenticator) CacheTokenInfo() error {
	data, err := json.Marshal(&CacheObj{auth.Secret})

	if err == nil {
		return auth.CacheCredentials(auth.Username, data, auth.Expiration)
	}

	return err
}

// Generate the contents that will be sent in the tokens claim body
func (auth *Authenticator) TokenBody(userData map[string]interface{}) map[string]interface{} {
	var content = make(map[string]interface{})
	var systems []interface{}

	content["user"] = auth.Username

	if name, exists := userData["name"]; exists {
		content["name"] = name
	}

	if uri, exists := userData["uri"]; exists {
		content["uri"] = uri
	}

	if groups, exists := userData["groups"]; exists {
		systems = auth.ResolveGroupsToSystems(groups.([]interface{}))
	}

	if list, exists := userData["systems"].([]interface{}); exists {
		systems = auth.ResolveDuplicateSystems(list, systems)
	}

	if len(systems) > 0 {
		content["systems"] = systems
	}

	content["exp"] = time.Now().Add(time.Duration(auth.Expiration) * time.Second).Unix() // Move expiration control to the token

	return content
}

func (auth *Authenticator) ResolveDuplicateSystems(userSystems []interface{}, systems []interface{}) []interface{} {
	for l, uSys := range userSystems {
		accessible := true

		// Check if the system already exists and override if found
		for i, system := range systems {
			if system.(map[string]interface{})["uri"] == uSys.(map[string]interface{})["uri"] {
				systems[i] = uSys
				userSystems = append(userSystems[:l], userSystems[l+1:]...) // When overriding remove the item from the list
				accessible = false
			}
		}

		// If non existent append the system into the list
		if accessible {
			systems = append(systems, uSys)
		}
	}

	return systems
}
