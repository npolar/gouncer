package gouncer

import (
	"encoding/json"
	"github.com/RDux/toki"
	"github.com/bradfitz/gomemcache/memcache"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Authorizer struct {
	Credentials // Anonymous credentials object
	Backend     *Backends
	ResponseHandler
}

func NewAuthorizer(w http.ResponseWriter, r *http.Request) *Authorizer {
	a := &Authorizer{}
	a.Writer = w
	a.HttpRequest = r
	a.Response = &AuthResponse{}

	return a
}

func (auth *Authorizer) AuthorizeRequest() {
	if err := auth.ParseAuthHeader(auth.HttpRequest.Header.Get("Authorization")); err == nil {
		req := auth.ParseRequestBody(auth.HttpRequest.Body)
		auth.ValidateRequest(req)
	} else {
		auth.NewError(http.StatusUnauthorized, "Unsupported Authorization method")
	}

	auth.Respond()
}

func (auth *Authorizer) ValidateRequest(req map[string]interface{}) {
	if system, exists := req["system"]; exists {
		if auth.Token == "" && auth.Password != "" {
			auth.ResolveUser(system.(string))
		} else {
			token := toki.NewJsonWebToken()
			if err := token.Parse(auth.Token); err != nil {
				auth.NewError(http.StatusUnauthorized, err.Error())
			}

			username := token.Claim.Content["user"].(string)
			mc := memcache.New(auth.Backend.Cache...)
			if item, err := mc.Get(username); err == nil {
				secret := item.Value
				if valid, err := token.Valid(string(secret)); valid {
					accessList := token.Claim.Content["systems"].(map[string]interface{})
					auth.SystemAccessible(system.(string), accessList)

					// Touch the memcache instance only when token validation succeeds
					mc.Touch(username, 600)
				} else {
					log.Println(err)
					auth.NewError(http.StatusUnauthorized, err.Error())
				}
			} else {
				log.Println(err)
				auth.NewError(http.StatusUnauthorized, err.Error())
			}
		}
	} else {
		auth.NewError(http.StatusUnauthorized, "No system info provided")
	}
}

func (auth *Authorizer) ResolveUser(system string) {
	// Hash password
	if response, err := http.Get(auth.Backend.UserDB + "/" + auth.Username); err == nil {
		body, err := ioutil.ReadAll(response.Body)
		defer response.Body.Close()

		if err == nil {
			var obj = make(map[string]interface{})
			json.Unmarshal(body, &obj)
			if tokenizer, err := NewTokenizer(auth.Password, obj); err == nil {

				if tokenizer.Authorized() {
					tokenizer.GroupDB = auth.Backend.GroupDB
					// Resolve groups into systems
					accessList := tokenizer.BulkResolveGroupsToSys()

					// Merge the systems in the user obj with those in the groups
					for key, val := range obj["systems"].(map[string]interface{}) {
						accessList[key] = val
					}

					auth.SystemAccessible(system, accessList)
				}
			}
		}
	}
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
			if auth.PathsMatch(sysUrl.Path, reqUrl.Path) {
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
