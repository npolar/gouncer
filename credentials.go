package gouncer

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

const (
	basicPattern  = "(?i)^Basic\\s([a-zA-Z0-9-_=]+)$"
	bearerPattern = "(?i)^Bearer\\s([a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+)$"
)

type Credentials struct {
	Username string
	Password string
	Token    string
	HashAlg  crypto.Hash
	Secret   string
}

func (creds *Credentials) ParseAuthHeader(value string) error {
	if basicAuth, rxp := creds.BasicAuth(value); basicAuth {
		matches := rxp.FindAllStringSubmatch(value, -1)
		return creds.ParseBasicAuth(matches[0][1])
	} else if bearerAuth, rxp := creds.BearerToken(value); bearerAuth {
		matches := rxp.FindAllStringSubmatch(value, -1)
		creds.Token = matches[0][1]
		return nil
	}

	return errors.New("Unsupported authorization method")
}

func (creds *Credentials) BasicAuth(authHeader string) (bool, *regexp.Regexp) {
	rxp := regexp.MustCompile(basicPattern)
	return rxp.MatchString(authHeader), rxp
}

func (creds *Credentials) BearerToken(authHeader string) (bool, *regexp.Regexp) {
	rxp := regexp.MustCompile(bearerPattern)
	return rxp.MatchString(authHeader), rxp
}

func (creds *Credentials) ParseBasicAuth(basicAuth string) error {
	if credString, err := creds.DecodeBase64(basicAuth); err == nil {
		segs, err := creds.SplitBasicAuth(credString)

		if err != nil {
			return err
		}

		creds.Username = segs[0]
		creds.Password = segs[1]

		return nil
	} else {
		return err
	}
}

func (creds *Credentials) SplitBasicAuth(content string) ([]string, error) {
	if strings.Contains(content, ":") {
		return strings.Split(content, ":"), nil
	} else {
		return []string{""}, errors.New("Malformed credentials payload")
	}
}

// DecodeBase64 decodes a base64 string
func (creds *Credentials) DecodeBase64(content string) (string, error) {
	if raw, err := base64.StdEncoding.DecodeString(content); err == nil {
		return string(raw), nil
	} else {
		return "", err
	}
}

// GenerateSecret uses the password hash the time and a random offset
// to generate a random secret used to sign the token with.
func (creds *Credentials) GenerateSecret() {
	creds.HashAlg = crypto.SHA1
	creds.Secret = creds.GenerateHash(creds.PasswordHash() + creds.TimeSalt())
}

func (creds *Credentials) TimeSalt() string {
	rand.Seed(time.Now().UTC().UnixNano())
	offset := rand.Intn(100000)

	return time.Now().UTC().Add(time.Minute * time.Duration(offset)).Format(time.RFC3339)
}

// PasswordHash returns the hashed password.
func (creds *Credentials) PasswordHash() string {
	return creds.GenerateHash(creds.Password)
}

// GenerateHash uses credentials.HashAlg to hash string content
func (creds *Credentials) GenerateHash(content string) string {
	alg := creds.HashAlg.New()
	io.WriteString(alg, content)
	return hex.EncodeToString(alg.Sum(nil))
}

// ConfigureUserHashAlg sets the hash algorithm to that in the userObj
func (creds *Credentials) ResolveHashAlg(hash string) {
	switch hash {
	case "sha1":
		creds.HashAlg = crypto.SHA1
	case "sha256":
		creds.HashAlg = crypto.SHA256
	case "sha384":
		creds.HashAlg = crypto.SHA384
	default:
		creds.HashAlg = crypto.SHA512
	}
}
