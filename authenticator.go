package gouncer

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"github.com/bradfitz/gomemcache/memcache"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type Authenticator struct {
	Cache    []string
	GroupDB  string
	UserDB   string
	Username string
	Password string
	Response *AuthResponse
	Error    *AuthError
}

type AuthResponse struct {
	Token string `json:"token,omitempty" xml:"Token"`
}

type AuthError struct {
	Status  int    `json:"status,omitempty" xml:"Status,attr"`
	Error   string `json:"error,omitempty" xml:"Error"`
	Message string `json:"message,omitempty" xml:"Message"`
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{
		Response: &AuthResponse{},
		Error:    &AuthError{},
	}
}

func (auth *Authenticator) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	auth.ExtractBasicAuth(r.Header.Get("Authorization"))
	auth.GenerateToken()

	// Check if an error occured. If so return error else return token
	if auth.Error.Error == "" {
		auth.TokenResponse(w, r)
	} else {
		auth.ErrorResponse(w, r)
	}
}

func (auth *Authenticator) TokenResponse(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("Accept") {
	case "application/json":
		jsonResponse, _ := json.Marshal(auth.Response)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(jsonResponse)
	case "application/xml", "text/xml":
		xmlResponse, _ := xml.MarshalIndent(auth.Response, "", "  ")
		xmlResponse = []byte(xml.Header + string(xmlResponse))
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Write(xmlResponse)
	default:
		w.Write([]byte(auth.Response.Token))
	}
}

func (auth *Authenticator) ErrorResponse(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(auth.Error.Status)

	switch r.Header.Get("Accept") {
	case "application/json":
		jsonResponse, _ := json.Marshal(auth.Error)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(jsonResponse)
	case "application/xml", "text/xml":
		xmlResponse, _ := xml.MarshalIndent(auth.Error, "", "  ")
		xmlResponse = []byte(xml.Header + string(xmlResponse))
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Write(xmlResponse)
	default:
		w.Write([]byte(auth.Error.String()))
	}
}

// @TODO move into the server layer so it can be reused in the authorizer layer
func (auth *Authenticator) ExtractBasicAuth(authHeader string) {
	if authHeader != "" {
		basicAuthRxp := regexp.MustCompile("(?i)Basic\\s(.+)$")
		matches := basicAuthRxp.FindAllStringSubmatch(authHeader, -1)
		if len(matches) > 0 {
			auth.ParseCredentials(matches[0][1])
		} else {
			auth.SetError(http.StatusUnauthorized, "Unauthorized", "Unsupported authorization method")
		}
	} else {
		auth.SetError(http.StatusUnauthorized, "Unauthorized", "Missing credentials")
	}
}

func (auth *Authenticator) DecodeBase64(content string) (string, error) {
	if raw, err := base64.StdEncoding.DecodeString(content); err == nil {
		return string(raw), nil
	} else {
		log.Println("[Authentication error]", err)
		return "", err
	}
}

func (auth *Authenticator) ParseCredentials(basicAuth string) {
	if credString, err := auth.DecodeBase64(basicAuth); err == nil {
		if strings.Contains(credString, ":") {
			parts := strings.Split(credString, ":")
			auth.Username = parts[0]
			auth.Password = parts[1]
		} else {
			auth.SetError(http.StatusBadRequest, "Bad Request", "Malformed credential payload")
		}
	} else {
		auth.SetError(http.StatusBadRequest, "Bad Request", "Malformed credential payload")
	}
}

func (auth *Authenticator) GenerateToken() {
	if tokenizer, err := NewTokenizer(auth.Password, auth.FetchUser()); err == nil {
		tokenizer.GroupDB = auth.GroupDB
		token, err := tokenizer.GenerateJWT()

		if err != nil {
			auth.SetError(http.StatusUnauthorized, "Unauthorized", err.Error())
		}

		if err = auth.CacheTokenInfo(tokenizer.Secret); err == nil {
			auth.Response.Token = token
		} else {
			auth.SetError(http.StatusInternalServerError, "Internal server error", err.Error())
		}
	} else {
		auth.SetError(http.StatusUnauthorized, "Unautherized", err.Error())
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
			auth.SetError(http.StatusInternalServerError, "Internal Server Error", "Error retrieving user info")
		}
	} else {
		auth.SetError(http.StatusInternalServerError, "Internal Server Error", "Error retrieving user info")
	}

	return caller
}

func (auth *Authenticator) SetError(status int, httpError string, message string) {
	auth.Error.Status = status
	auth.Error.Error = httpError
	auth.Error.Message = message
}

func (authErr *AuthError) String() string {
	return strconv.Itoa(authErr.Status) + " - " + authErr.Error + ": " + authErr.Message
}
