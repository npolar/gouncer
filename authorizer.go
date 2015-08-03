package gouncer

import (
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
	return &Authorizer{ResponseHandler: h}
}

// AuthorizeRequest handles authorization checking with the provided system and credentials
func (auth *Authorizer) AuthorizeRequest() {
	err := auth.ParseAuthHeader(auth.HttpRequest.Header.Get("Authorization"))

	if err == nil {
		var req = make(map[string]interface{})
		err = DecodeJsonRequest(auth.HttpRequest.Body, &req)
		auth.ValidateRequest(req)
	}

	if err != nil {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
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
	var err error

	valid, cerr := auth.ValidBasicAuth()
	err = cerr

	if valid {
		var accessList []interface{}

		if groups, exists := auth.UserInfo["groups"].([]interface{}); exists {
			accessList = auth.ResolveGroupsToSystems(groups)
		}

		if list, exists := auth.UserInfo["systems"].([]interface{}); exists {
			accessList = auth.ResolveDuplicateSystems(list, accessList)
		}

		auth.SystemAccessible(system, accessList)
	}

	if err != nil {
		auth.NewError(http.StatusUnauthorized, err.Error())
	}
}

// AuthorizedToken checks if the token has access rights for the system
func (auth *Authorizer) AuthorizedToken(system string) {
	var err error

	valid, cerr := auth.ValidToken()
	err = cerr

	if valid {
		var accessList []interface{}

		if auth.Jwt.Claim.Content["systems"] != nil {
			accessList = auth.Jwt.Claim.Content["systems"].([]interface{})
		}

		auth.SystemAccessible(system, accessList)
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

// SystemAccessible will check the users system list against the system we are authorizing.
// If a match is found (exact|wildacrd) we will set the AccessRights in the auth.Response
func (auth *Authorizer) SystemAccessible(system string, accessList []interface{}) {
	match := false
	var r interface{}
	for _, accessItem := range accessList {
		sysUrl, _ := url.Parse(accessItem.(map[string]interface{})["uri"].(string))
		reqUrl, _ := url.Parse(system)
		if sysUrl.Host == reqUrl.Host {
			if auth.ExactPathMatch(sysUrl.Path, reqUrl.Path) || auth.WildcardPathMatch(sysUrl.Path, reqUrl.Path) {
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
