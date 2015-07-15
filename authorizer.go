package gouncer

import (
	"encoding/json"
	"github.com/npolar/toki"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Authorizer struct {
	Credentials
	Expiration int32 // Token expriation time. Used on touch.
	*ResponseHandler
}

// NewAuthorizer configures the Authorizer and returns a pointer
func NewAuthorizer(h *ResponseHandler) *Authorizer {
	a := &Authorizer{}
	a.ResponseHandler = h

	return a
}

// AuthorizeRequest handles authorization checking with the provided system and credentials
func (auth *Authorizer) AuthorizeRequest() {
	if err := auth.ParseAuthHeader(auth.HttpRequest.Header.Get("Authorization")); err == nil {
		req := auth.ParseRequestBody(auth.HttpRequest.Body)
		auth.HttpRequest.Body.Close()
		auth.ValidateRequest(req)
	} else {
		auth.NewError(http.StatusUnauthorized, "Unsupported Authorization method")
	}

	auth.Respond()
}

// ValidateRequest checks if the caller has any access rights on the system
func (auth *Authorizer) ValidateRequest(req map[string]interface{}) {
	if system, exists := req["system"]; exists {
		if auth.Token == "" && auth.Password != "" {
			auth.AuthorizedUser(system.(string))
		} else {
			auth.AuthorizedToken(system.(string))
		}
	} else {
		auth.NewError(http.StatusUnauthorized, "No system info provided")
	}
}

// AutorizedUser checks if the user has any access rights for the system
func (auth *Authorizer) AuthorizedUser(system string) {
	userInfo, err := auth.FetchUser()

	if err == nil {
		auth.ResolveHashAlg(userInfo["hash"].(string))

		valid, verr := auth.ValidatePasswordHash(userInfo["password"].(string))
		err = verr

		if valid {
			var accessList []interface{}

			if groups, exists := userInfo["groups"].([]interface{}); exists {
				accessList = auth.ResolveGroupsToSystems(groups)
			}

			if list, exists := userInfo["systems"].([]interface{}); exists {
				accessList = auth.ResolveDuplicateSystems(list, accessList)
			}

			auth.SystemAccessible(system, accessList)
		}
	}

	if err != nil {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

// AuthorizedToken checks if the token has access rights for the system
func (auth *Authorizer) AuthorizedToken(system string) {
	token := toki.NewJsonWebToken()
	err := token.Parse(auth.Token)

	if err == nil {
		username := token.Claim.Content["user"].(string)
		item, cerr := auth.Backend.Cache.Get(username)
		err = cerr

		if err == nil {
			secret := string(item.Value)

			valid, verr := token.Valid(secret)
			err = verr

			if valid {
				var accessList []interface{}

				if token.Claim.Content["systems"] != nil {
					accessList = token.Claim.Content["systems"].([]interface{})
				}

				auth.SystemAccessible(system, accessList)
				// Touch the memcache instance only when token validation succeeds
				// @TODO review refresh strategy (can cause infinit keep-alive)
				auth.Backend.Cache.Touch(username, auth.Expiration)
			}
		}
	}

	if err != nil {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (auth *Authorizer) ResolveDuplicateSystems(userSystems []interface{}, systems []interface{}) []interface{} {
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

// ParseRequestBody parses the json body of the authorization request
func (auth *Authorizer) ParseRequestBody(body io.ReadCloser) map[string]interface{} {
	raw, err := ioutil.ReadAll(body)
	defer body.Close()

	if err != nil {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}

	response := make(map[string]interface{})
	json.Unmarshal(raw, &response)

	return response
}

// SystemAccessible will check the users system list against the system we are authorizing.
// If a match is found (exact|wildacrd) we will set the AccessRights in the auth.Response
func (auth *Authorizer) SystemAccessible(system string, accessList []interface{}) {
	match := false
	var r interface{}
	for _, accessItem := range accessList {
		sysUrl, _ := url.Parse(accessItem.(map[string]interface{})["uri"].(string))
		reqUrl, _ := url.Parse(system)
		if sysUrl.Host == reqUrl.Host {
			if auth.ExactPathMatch(sysUrl.Path, reqUrl.Path) {
				match = true
				r = accessItem.(map[string]interface{})["rights"]
			} else if r == nil && auth.WildcardPathMatch(sysUrl.Path, reqUrl.Path) {
				match = true
				r = accessItem.(map[string]interface{})["rights"]
			}
		}
	}

	if match {
		auth.Response.AccessRights = r
	} else {
		auth.NewError(http.StatusUnauthorized, "You do not have access to this system")
	}
}

// ExactPathMatch checks if the two paths are the same
func (auth *Authorizer) ExactPathMatch(pathA string, pathB string) bool {
	return pathA == pathB
}

// WildcardPathMatch checks if a path partially matches and ends in a wildcard
func (auth *Authorizer) WildcardPathMatch(pathA string, pathB string) bool {
	segsA := strings.Split(pathA, "/")
	segsB := strings.Split(pathB, "/")

	match := true

	for i, seg := range segsA {
		if segsB[i] != seg && seg != "*" {
			match = false
		}
	}

	return match
}
