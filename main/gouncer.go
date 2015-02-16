package main

import (
	"fmt"
	"github.com/RDux/gouncer"
	"github.com/codegangsta/cli"
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
	gouncer.Usage = "A high performance auth API."
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
			Name:   "certificate, c",
			Usage:  "Specify ssl certificate. [REQUIRED]",
			EnvVar: "GOUNCER_SSL_CERT",
		},
		cli.StringFlag{
			Name:   "group, g",
			Value:  "https://localhost:6984/groups",
			Usage:  "Set (CouchDB) group database",
			EnvVar: "GOUNCER_GROUP_DB",
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
			Value:  &cli.StringSlice{"http://localhost:11211"},
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
			Value:  "https://localhost:6984/users",
			Usage:  "Set (CouchDB) user database.",
			EnvVar: "GOUNCER_USER_DB",
		},
	}
}

func StartGouncerServer(c *cli.Context) {
	CheckSSL(c)

	// Create a new server instance and set the right options
	srv := gouncer.NewServer(":" + c.String("port"))
	srv.Certificate = c.String("certificate")
	srv.CertificateKey = c.String("key")
	srv.Cache = c.StringSlice("memcache")
	srv.UserDB = c.String("userdb")
	srv.GroupDB = c.String("groupdb")

	// Transfer version and description info to the server layer
	srv.Name = c.App.Name
	srv.Version = c.App.Version
	srv.Usage = c.App.Usage

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
