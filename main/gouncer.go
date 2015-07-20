package main

import (
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/naoina/toml"
	"github.com/npolar/gouncer"
	"io/ioutil"
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

// @TODO define flags for CORS rules ?? Config file
func LoadFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "algorithm, a",
			Value:  "HS256",
			Usage:  "Specify token signing algorithm",
			EnvVar: "GOUNCER_ALGORITHM",
		},
		cli.StringFlag{
			Name:   "certificate, c",
			Usage:  "Specify ssl certificate. [REQUIRED]",
			EnvVar: "GOUNCER_SSL_CERT",
		},
		cli.StringFlag{
			Name:   "config",
			Usage:  "Specify a TOML configuration file to load.",
			EnvVar: "GOUNCER_CONF",
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
		cli.StringFlag{
			Name:   "hostname, host",
			Usage:  "Set the servers hostname. Used when building confirmation uri's",
			EnvVar: "GOUNCER_HOSTNAME",
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
		cli.IntFlag{
			Name:   "revalidation, r",
			Value:  1800,
			Usage:  "Token revalidation time in seconds",
			EnvVar: "GOUNCER_TOKEN_REVALIDATE",
		},
		cli.StringFlag{
			Name:   "smtp, s",
			Usage:  "Set SMTP server to use for notification mails",
			EnvVar: "GOUNCER_SMTP",
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
	var srv *gouncer.Server

	// Create a new server instance with the appropriate  configuration
	if cfg := c.String("config"); cfg != "" {
		srv = ServerFromConf(cfg)
	} else {
		srv = ServerFromCli(c)
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

// ServerFromConf generates a server instance with the settings
// specified in the specified config file. All other command line
// arguments are igored in this operation mode
func ServerFromConf(cfg string) *gouncer.Server {
	conf, err := ioutil.ReadFile(cfg)

	if err != nil {
		log.Fatalln("Error reading config", err.Error())
	}

	var gcfg gouncer.Config

	if err := toml.Unmarshal(conf, &gcfg); err != nil {
		log.Fatalln("Error parsing config", err.Error())
	}

	return gouncer.NewServer(&gcfg)
}

// ServerFromCli uses the cli arguments to configure a server instance
func ServerFromCli(c *cli.Context) *gouncer.Server {
	CheckSSL(c)

	// Initialize configuration components from cli
	core := &gouncer.Core{c.String("hostname"), ":" + c.String("port"), c.Bool("jsonp"), c.String("log")}
	ssl := &gouncer.Ssl{c.String("certificate"), c.String("key")}

	backend := &gouncer.Backend{
		Couchdb:  c.String("couchdb"),
		Userdb:   c.String("userdb"),
		Groupdb:  c.String("groupdb"),
		Memcache: c.StringSlice("memcache"),
		Smtp:     c.String("smtp"),
	}

	token := &gouncer.Token{c.String("algorithm"), int32(c.Int("expiration")), int32(c.Int("revalidation"))}

	// Create configuration
	cfg := &gouncer.Config{
		Core:    core,
		Ssl:     ssl,
		Backend: backend,
		Token:   token,
	}

	return gouncer.NewServer(cfg)
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
