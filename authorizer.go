package gouncer

import (
	"encoding/json"
	"github.com/RDux/toki"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Authorizer struct {
	Credentials
	Backend    *Backend
	Expiration int32 // Token expriation time. Used on touch.
	*ResponseHandler
}

func NewAuthorizer(h *ResponseHandler) *Authorizer {
	a := &Authorizer{}
	a.ResponseHandler = h

	return a
}

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

		if auth.PasswordHash() == userInfo["password"].(string) {
			var accessList = make(map[string]interface{})

			if groups, exists := userInfo["groups"].([]interface{}); exists {
				accessList = auth.ResolveGroupsToSystems(groups)
			}

			if systems, exists := userInfo["systems"]; exists {
				for system, rights := range systems.(map[string]interface{}) {
					accessList[system] = rights
				}
			}

			auth.SystemAccessible(system, accessList)
		}
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
				accessList := token.Claim.Content["systems"].(map[string]interface{})
				auth.SystemAccessible(system, accessList)

				// Touch the memcache instance only when token validation succeeds
				auth.Backend.Cache.Touch(username, auth.Expiration)
			}
		}
	}

	if err != nil {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (auth *Authorizer) FetchUser() (map[string]interface{}, error) {
	couch := NewCouch(auth.Backend.Server, auth.Backend.UserDB)
	return couch.Get(auth.Username)
}

func (auth *Authorizer) ResolveGroupsToSystems(groups []interface{}) map[string]interface{} {
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

func (auth *Authorizer) SystemAccessible(system string, accessList map[string]interface{}) {
	match := false
	var r interface{}
	for accessItem, rights := range accessList {
		sysUrl, _ := url.Parse(accessItem)
		reqUrl, _ := url.Parse(system)
		if sysUrl.Host == reqUrl.Host {
			if auth.ExactPathMatch(sysUrl.Path, reqUrl.Path) {
				match = true
				r = rights
			} else if r == nil && auth.PathsMatch(sysUrl.Path, reqUrl.Path) {
				match = true
				r = rights
			}
		}
	}

	if match {
		auth.Response.AccessRights = r
	} else {
		auth.NewError(http.StatusUnauthorized, "You do not have access to this system")
	}
}

func (auth *Authorizer) ExactPathMatch(pathA string, pathB string) bool {
	segsA := strings.Split(pathA, "/")
	segsB := strings.Split(pathB, "/")

	match := true

	for i, seg := range segsA {
		if segsB[i] != seg {
			match = false
		}
	}

	return match
}

func (auth *Authorizer) PathsMatch(pathA string, pathB string) bool {
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
