package main

import (
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/npolar/gouncer"
	"log"
	"os"
)

func main() {
	InitGouncer()
}

func InitGouncer() {
	gouncer := cli.NewApp()
	gouncer.Version = "0.0.1"
	gouncer.Name = "gouncer"
	gouncer.Usage = "A high performance auth API"
	gouncer.Author = "Ruben Dens"
	gouncer.Email = "ruben.dens@npolar.no"
	gouncer.Flags = LoadFlags()
	gouncer.Action = StartGouncerServer
	gouncer.Run(os.Args)
}

// @TODO define flags for token algorithm
// @TODO define flags for CORS rules ?? Config file
func LoadFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "algorithm, a",
			Value:  "HS256",
			Usage:  "Specify token signing algorithm",
			EnvVar: "Gouncer_ALGORITHM",
		},
		cli.StringFlag{
			Name:   "certificate, c",
			Usage:  "Specify ssl certificate. [REQUIRED]",
			EnvVar: "GOUNCER_SSL_CERT",
		},
		cli.StringFlag{
			Name:   "couchdb, db",
			Value:  "http://localhost:6984",
			Usage:  "Specify CouchDB address",
			EnvVar: "GOUNCER_COUCHDB",
		},
		cli.IntFlag{
			Name:   "expiration, e",
			Value:  1200,
			Usage:  "Token expiration time in seconds.",
			EnvVar: "GOUNCER_TOKEN_EXPIRE",
		},
		cli.StringFlag{
			Name:   "groupdb, g",
			Value:  "groups",
			Usage:  "Set group database",
			EnvVar: "GOUNCER_GROUP_DB",
		},
		cli.BoolFlag{
			Name:  "jsonp, j",
			Usage: "Enable JsonP support",
		},
		cli.StringFlag{
			Name:   "key, k",
			Usage:  "Specify ssl certificate-key. [REQUIRED]",
			EnvVar: "GOUNCER_SSL_KEY",
		},
		cli.StringFlag{
			Name:  "log, l",
			Usage: "Log to specified file instead of STDOUT.",
		},
		cli.StringSliceFlag{
			Name:   "memcache, m",
			Value:  &cli.StringSlice{"127.0.0.1:11211"},
			Usage:  "Configure memcache instance(s).",
			EnvVar: "GOUNCER_CACHE",
		},
		cli.StringFlag{
			Name:  "port, p",
			Value: "8950",
			Usage: "Server port.",
		},
		cli.StringFlag{
			Name:   "userdb, u",
			Value:  "users",
			Usage:  "Set user database.",
			EnvVar: "GOUNCER_USER_DB",
		},
	}
}

// StartGouncerServer initializes and starts a new server instance
// with the provided command line options.
func StartGouncerServer(c *cli.Context) {
	CheckSSL(c)

	// Create a new server instance and set the right options
	srv := gouncer.NewServer(":" + c.String("port"))
	srv.Certificate = c.String("certificate")
	srv.CertificateKey = c.String("key")
	srv.Expiration = int32(c.Int("expiration"))
	srv.JsonP = c.Bool("jsonp")
	srv.TokenAlg = c.String("algorithm")

	// Configure the server backend
	srv.Backend = &gouncer.Backend{
		Server:  c.String("couchdb"),
		Cache:   srv.NewCache(c.StringSlice("memcache")),
		UserDB:  c.String("userdb"),
		GroupDB: c.String("groupdb"),
	}

	// Transfer version and description info to the server layer
	srv.Name = c.App.Name
	srv.Version = c.App.Version
	srv.Description = c.App.Usage

	// Print the awesome ASCII banner
	PrintBanner()

	// Start the auth server
	srv.Start()
}

// CeckSSL looks at the certificate and certificate-key flags. If
// the are empty an error is thrown and the server exits with status 1
func CheckSSL(c *cli.Context) {
	var missing string
	switch {
	case c.String("certificate") == "":
		missing = "certificate"
	case c.String("key") == "":
		missing = "certificate-key"
	}

	if missing != "" {
		log.Fatal("[SSL error] missing: " + missing + ". See gouncer --help for more info.")
	}
}

// ASCII art banner printed to STDOUT when the server starts
func PrintBanner() {
	fmt.Println("                                                                         ")
	fmt.Println("      _/_/_/    _/_/    _/    _/  _/      _/    _/_/_/  _/_/_/_/  _/_/_/ ")
	fmt.Println("   _/        _/    _/  _/    _/  _/_/    _/  _/        _/        _/    _/")
	fmt.Println("  _/  _/_/  _/    _/  _/    _/  _/  _/  _/  _/        _/_/_/    _/_/_/   ")
	fmt.Println(" _/    _/  _/    _/  _/    _/  _/    _/_/  _/        _/        _/    _/  ")
	fmt.Println("  _/_/_/    _/_/      _/_/    _/      _/    _/_/_/  _/_/_/_/  _/    _/   ")
	fmt.Println("				                                                                  ")
}
