package gouncer

import (
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/rs/cors"
	"log"
	"net/http"
)

type Server struct {
	Port           string
	Backend        *Backend
	Certificate    string
	CertificateKey string
	TokenAlg       string
	Expiration     int32
	JsonP          bool
	Info
}

type Backend struct {
	Cache   *memcache.Client
	GroupDB string
	UserDB  string
	Server  string
}

type Info struct {
	Version     string `json:"version,omitempty" xml:",omitempty"`
	Name        string `json:"name,omitempty" xml:",omitempty"`
	Description string `json:"description,omitempty" xml:",omitempty"`
}

func NewServer(port string) *Server {
	return &Server{Port: port}
}

// Start sets up gouncers routes and handlers and then starts a TLS server
func (srv *Server) Start() {
	// Confiugre CORS
	corsRules := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"POST", "GET", "HEAD", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Content-Type", "Authorization", "Origin"},
	})

	// Wrap the http handlers in a cors handler
	corsInfo := corsRules.Handler(http.HandlerFunc(srv.InfoHandler))
	corsAuthentication := corsRules.Handler(http.HandlerFunc(srv.AuthenticationHandler))
	corsAuthorization := corsRules.Handler(http.HandlerFunc(srv.AuthorizationHandler))

	// Define routes
	http.Handle("/", corsInfo)
	http.Handle("/authenticate/", corsAuthentication)
	http.Handle("/authorize/", corsAuthorization)

	// Attempt to start the server. On error server exits with status 1
	if err := http.ListenAndServeTLS(srv.Port, srv.Certificate, srv.CertificateKey, nil); err != nil {
		log.Fatal(err)
	}
}

// Authentication handler checks the method and delegates a token request
func (srv *Server) AuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "GET" {
		// Configure the Authenticator
		authenticator := NewAuthenticator(handler)
		authenticator.Backend = srv.Backend
		authenticator.TokenAlg = srv.TokenAlg
		authenticator.Expiration = srv.Expiration

		// Execute a token request
		authenticator.HandleTokenRequest()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "")
		handler.Respond()
	}

}

// AuthorizationHandler checks the http method and delegates the request to the authorizer
func (srv *Server) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "POST" {
		// Configure the Authorizer
		authorizer := NewAuthorizer(handler)
		authorizer.Backend = srv.Backend
		authorizer.Expiration = srv.Expiration

		// Handle authorization
		authorizer.AuthorizeRequest()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "")
		handler.Respond()
	}

}

// NewCache starts a new memcache client for the provided servers
func (srv *Server) NewCache(servers []string) *memcache.Client {
	return memcache.New(servers...)
}

// ConfigureHandler sets up the response handler
func (srv *Server) ConfigureHandler(w http.ResponseWriter, r *http.Request) *ResponseHandler {
	handler := NewResponseHandler(w, r)
	handler.JsonP = srv.JsonP

	return handler
}

// @TODO make motd configurable
// InfoHandler takes care of root requests and displays auth server info as the requested format
func (srv *Server) InfoHandler(w http.ResponseWriter, r *http.Request) {
	handler := srv.ConfigureHandler(w, r)
	handler.Response.Info = &srv.Info

	handler.Respond()
}
