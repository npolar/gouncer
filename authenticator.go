package gouncer

import (
	"encoding/base64"
	"encoding/json"
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
	Writer   http.ResponseWriter
	Request  *http.Request
}

type AuthResponse struct {
	Token string `json:"token,omitempty"`
}

type AuthError struct {
	Status  int    `json:"status,omitempty"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

func NewAuthenticator(w http.ResponseWriter, r *http.Request) *Authenticator {
	return &Authenticator{
		Writer:  w,
		Request: r,
	}
}

func (auth *Authenticator) HandleTokenRequest() {
	auth.ExtractBasicAuth(auth.Request.Header.Get("Authorization"))
	auth.GenerateToken()

	// Check if an error occured. If so return error else return token
	if auth.Error == nil {
		auth.TokenResponse()
	} else {
		auth.ErrorResponse()
	}
}

func (auth *Authenticator) TokenResponse() {
	switch auth.Request.Header.Get("Accept") {
	case "application/json":
		jsonResponse, _ := json.Marshal(auth.Response)
		auth.Writer.Write(jsonResponse)
	default:
		auth.Writer.Write([]byte(auth.Response.Token))
	}
}

func (auth *Authenticator) ErrorResponse() {
	auth.Writer.WriteHeader(auth.Error.Status)

	switch auth.Request.Header.Get("Accept") {
	case "application/json":
		jsonResponse, _ := json.Marshal(auth.Error)
		auth.Writer.Write(jsonResponse)
	default:
		auth.Writer.Write([]byte(auth.Error.String()))
	}
}

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
	auth.Response = &AuthResponse{
		Token: "faketokenz...",
	}
}

func (auth *Authenticator) SetError(status int, httpError string, message string) {
	auth.Error = &AuthError{
		Status:  status,
		Error:   httpError,
		Message: message,
	}
}

func (authErr *AuthError) String() string {
	return strconv.Itoa(authErr.Status) + " - " + authErr.Error + ": " + authErr.Message
}
