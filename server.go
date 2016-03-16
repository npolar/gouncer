package gouncer

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/rs/cors"
)

type Server struct {
	*Config
	Info
}

// Config for the server
type Config struct {
	*Core
	*Ssl
	*Backend
	*Token
	Registrations map[string]Registration
	*MailConfig
}

// Core server setup
type Core struct {
	Hostname string
	Port     string
	Jsonp    bool
	Log      string
}

// Ssl certificate and key config
type Ssl struct {
	Certificate string
	Key         string
}

// Backend configuration info
type Backend struct {
	Memcache []string
	Cache    *memcache.Client
	Groupdb  string
	Userdb   string
	Couchdb  string
	Smtp     string
	Sicas    string
	Logger   *log.Logger
}

// Token information
type Token struct {
	Algorithm  string
	Expiration int32
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

func NewServer(cfg *Config) *Server {

	srv := &Server{Config: cfg}
	srv.Cache = srv.NewCache(srv.Memcache)

	return srv
}

// Start sets up gouncers routes and handlers and then starts a TLS server
func (srv *Server) Start() {
	// Confiugre CORS
	corsRules := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"POST", "GET", "HEAD", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Content-Type", "Authorization", "Origin"},
	})

	handlers := []HandlerDef{
		HandlerDef{[]string{"/"}, srv.InfoHandler},
		HandlerDef{[]string{"/authenticate", "/authenticate/"}, srv.AuthenticationHandler},
		HandlerDef{[]string{"/authorize", "/authorize/"}, srv.AuthorizationHandler},
		HandlerDef{[]string{"/key", "/key/"}, srv.ReadKeyHandler},
		HandlerDef{[]string{"/reset", "/reset/"}, srv.ResetHandler},
	}

	// If an smtp server is configured enable the account registration routes
	if srv.Smtp != "" {
		regHandlers := []HandlerDef{
			HandlerDef{[]string{"/register", "/register/"}, srv.RegistrationHandler},
			HandlerDef{[]string{"/unregister", "/unregister/"}, srv.UnRegHandler},
			HandlerDef{[]string{"/cancel", "/cancel/"}, srv.CancelationHandler},
			HandlerDef{[]string{"/confirm", "/confirm/"}, srv.ConfirmationHandler},
			HandlerDef{[]string{"/onetime", "/onetime/"}, srv.OneTimeHandler},
		}

		handlers = append(handlers, regHandlers...)
	}

	for _, h := range handlers {
		for _, r := range h.Routes {
			http.Handle(r, corsRules.Handler(http.HandlerFunc(h.Handler)))
		}
	}

	// Setup the global logger
	logFile, err := os.OpenFile(srv.Core.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)

	if err != nil {
		log.Fatalln("Error creating logfile:", err)
	}

	srv.Logger = log.New(logFile, "", log.Ldate|log.Ltime|log.Lshortfile)

	// Attempt to start the server. On error server exits with status 1
	if err := http.ListenAndServeTLS(srv.Port, srv.Certificate, srv.Key, nil); err != nil {
		srv.Logger.Fatal(err)
	}

	logFile.Close()
}

// Authentication handler checks the method and delegates a token request
func (srv *Server) AuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[AUTHENTICATION] -", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "GET" {
		// Configure the Authenticator
		authenticator := NewAuthenticator(handler)
		authenticator.Backend = srv.Backend
		authenticator.Token = srv.Token

		// Execute a token request
		authenticator.HandleTokenRequest()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [GET]")
	}

	handler.Respond()
}

func (srv *Server) OneTimeHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[ONETIME] -", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)

	if r.Method == "POST" {
		onetime := NewOneTimePassword(handler)
		onetime.Backend = srv.Backend
		onetime.MailConfig = srv.MailConfig

		onetime.RequestPassword()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [POST]")
	}

	handler.Respond()
}

// AuthorizationHandler checks the http method and delegates the request to the authorizer
func (srv *Server) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[AUTHORIZATION]", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "POST" {
		// Configure the Authorizer
		authorizer := NewAuthorizer(handler)
		authorizer.Backend = srv.Backend
		authorizer.Expiration = srv.Expiration

		// Handle authorization
		authorizer.AuthorizeRequest()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [POST]")
	}

	handler.Respond()
}

func (srv *Server) ReadKeyHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[READ-KEY]", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "POST" {
		// Configure the Key Handler
		key := NewKeyHandler(handler)
		key.Backend = srv.Backend

		key.HandleRequest()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [POST]")
	}

	handler.Respond()
}

func (srv *Server) ResetHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[RESET] -", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)

	if r.Method == "POST" {
		// Configure the ResetHandler
		reset := NewResetHandler(handler)
		reset.Backend = srv.Backend

		// Handle reset
		reset.UserPassword()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [POST]")
	}

	handler.Respond()
}

// RegistrationHandler receives a regestration request and initiates the registration process
func (srv *Server) RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[REGISTRATION] -", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "POST" {
		registration := NewRegistration(handler)
		registration.Core = srv.Core
		registration.Backend = srv.Backend
		registration.Groups = srv.Registrations
		registration.MailConfig = srv.MailConfig
		registration.Submit()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [POST]")
	}

	handler.Respond()
}

// UnregHandler allows a user to unregister by sending a delete request with valid auth information
func (srv *Server) UnRegHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[UN-REGISTER] -", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "DELETE" {
		registration := NewRegistration(handler)
		registration.Core = srv.Core
		registration.Backend = srv.Backend
		registration.Groups = srv.Registrations
		registration.MailConfig = srv.MailConfig
		registration.Cancel()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [DELETE]")
	}

	handler.Respond()
}

func (srv *Server) CancelationHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[CANCELLATION] -", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "GET" {
		cancellation := NewCancellation(handler)
		cancellation.Backend = srv.Backend
		cancellation.Confirm()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [GET]")
	}

	handler.Respond()
}

// ConfirmationHandler receives a confirmation request and initiates the confirmation sequence
func (srv *Server) ConfirmationHandler(w http.ResponseWriter, r *http.Request) {
	srv.Logger.Println("[CONFIRMATION] -", r.Proto, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	handler := srv.ConfigureHandler(w, r)
	if r.Method == "GET" {
		confirm := NewConfirm(handler)
		confirm.Backend = srv.Backend
		confirm.Registration()
	} else {
		handler.NewError(http.StatusMethodNotAllowed, "Allowed methods for this endpoint: [GET]")
	}

	handler.Respond()
}

// NewCache starts a new memcache client for the provided servers
func (srv *Server) NewCache(servers []string) *memcache.Client {
	return memcache.New(servers...)
}

// ConfigureHandler sets up the response handler
func (srv *Server) ConfigureHandler(w http.ResponseWriter, r *http.Request) *ResponseHandler {
	handler := NewResponseHandler(w, r)
	handler.JsonP = srv.Jsonp

	return handler
}

// @TODO make motd configurable
// InfoHandler takes care of root requests and displays auth server info as the requested format
func (srv *Server) InfoHandler(w http.ResponseWriter, r *http.Request) {
	handler := srv.ConfigureHandler(w, r)
	handler.Response.Info = &srv.Info

	handler.Respond()
}
