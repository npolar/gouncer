package gouncer

import (
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/rs/cors"
	"log"
	"net/http"
)

type Server struct {
	Port           string
	Certificate    string
	CertificateKey string
	Backend        *Backend
	Info
}

type Backend struct {
	Cache   *memcache.Client
	GroupDB string
	UserDB  string
	Server  string
}

type Info struct {
	Version string
	Name    string
	Usage   string
}

func NewServer(port string) *Server {
	return &Server{
		Port: port,
	}
}

func (srv *Server) Start() {
	// Confiugre CORS
	corsRules := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedMethods:   []string{"POST", "GET", "HEAD", "OPTIONS"},
	})

	// Wrap the http handlers in a cors handler
	corsInfo := corsRules.Handler(http.HandlerFunc(srv.InfoHandler))
	corsAuthentication := corsRules.Handler(http.HandlerFunc(srv.AuthenticationHandler))
	corsAuthorization := corsRules.Handler(http.HandlerFunc(srv.AuthorizationHandler))

	// Define routes
	http.Handle("/", corsInfo)
	http.Handle("/authenticate", corsAuthentication)
	http.Handle("/authorize", corsAuthorization)

	// Attempt to start the server. On error server exits with status 1
	if err := http.ListenAndServeTLS(srv.Port, srv.Certificate, srv.CertificateKey, nil); err != nil {
		log.Fatal(err)
	}
}

// Authentication handler checks the method and delegates a token request
func (srv *Server) AuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Configure the Authenticator instance
		authenticator := NewAuthenticator(w, r)
		authenticator.Backend = srv.Backend

		// Execute a token request
		authenticator.HandleTokenRequest()
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Error 405: Method not allowed\n"))
	}
}

func (srv *Server) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		authorizer := NewAuthorizer(w, r)
		authorizer.Backend = srv.Backend
		authorizer.AuthorizeRequest()
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Error 405: Method not allowed\n"))
	}
}

func (srv *Server) NewCache(servers []string) *memcache.Client {
	return memcache.New(servers...)
}

// @TODO make motd configurable
func (srv *Server) InfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte("{\"name\":\"" + srv.Name + "\", \"version\": \"" + srv.Version + "\", \"description\": \"" + srv.Usage + "\", \"message\": \"g(B)ouncer - Check people at the door!\"}"))
}
