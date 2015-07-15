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
	Smtp    string
}

type Info struct {
	Version     string `json:"version,omitempty" xml:",omitempty"`
	Name        string `json:"name,omitempty" xml:",omitempty"`
	Description string `json:"description,omitempty" xml:",omitempty"`
}

type HandlerDef struct {
	Routes  []string
	Handler http.HandlerFunc
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

	handlers := [...]HandlerDef{
		HandlerDef{[]string{"/"}, srv.InfoHandler},
		HandlerDef{[]string{"/authenticate", "/authenticate/"}, srv.AuthenticationHandler},
		HandlerDef{[]string{"/authorize", "/authorize/"}, srv.AuthorizationHandler},
		HandlerDef{[]string{"/register", "/register/"}, srv.RegistrationHandler},
		HandlerDef{[]string{"/confirm", "/confirm/"}, srv.ConfirmationHandler},
	}

	for _, h := range handlers {
		for _, r := range h.Routes {
			http.Handle(r, corsRules.Handler(http.HandlerFunc(h.Handler)))
		}
	}

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

// RegistrationHandler receives a regestration request and initiates the registration process
func (srv *Server) RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "POST" {
		registration := NewRegistration(handler)
		registration.Backend = srv.Backend
		registration.Submit()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "")
		handler.Respond()
	}
}

// ConfirmationHandler receives a confirmation request and initiates the confirmation sequence
func (srv *Server) ConfirmationHandler(w http.ResponseWriter, r *http.Request) {
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "GET" {
		confirmation := NewConfirmation(handler)
		confirmation.Backend = srv.Backend
		confirmation.ConfirmRegistration()
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
