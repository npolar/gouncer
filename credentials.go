package gouncer

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
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
	Backend  *Backend
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

	return errors.New("Unsupported credsorization method")
}

func (creds *Credentials) BasicAuth(credsHeader string) (bool, *regexp.Regexp) {
	rxp := regexp.MustCompile(basicPattern)
	return rxp.MatchString(credsHeader), rxp
}

func (creds *Credentials) BearerToken(credsHeader string) (bool, *regexp.Regexp) {
	rxp := regexp.MustCompile(bearerPattern)
	return rxp.MatchString(credsHeader), rxp
}

func (creds *Credentials) ParseBasicAuth(basicAuth string) error {
	if credString, err := creds.DecodeBase64(basicAuth); err == nil {
		segs, err := creds.SplitBasicAuth(credString)

		if err == nil {
			if len(segs[0]) > 0 && len(segs[1]) > 0 {
				creds.Username = segs[0]
				creds.Password = segs[1]
			} else {
				err = errors.New("Empty password field")
			}
		}

		return err
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
	creds.Secret = creds.GenerateHash(creds.PasswordHash() + creds.TimeSalt() + creds.CharSalt(16))
}

func (creds *Credentials) TimeSalt() string {
	rand.Seed(time.Now().UTC().UnixNano())
	offset := rand.Intn(100000)

	return time.Now().UTC().Add(time.Minute * time.Duration(offset)).Format(time.RFC3339)
}

// CharSalt generates a random character string with the size specified in the argument
func (creds *Credentials) CharSalt(size int) string {
	var salt []byte
	dictionary := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789")
	rand.Seed(time.Now().UTC().UnixNano())

	for i := 0; i < size; i++ {
		salt = append(salt, dictionary[rand.Intn(len(dictionary))])
	}

	return string(salt)
}

// PasswordHash returns the hashed password.
func (creds *Credentials) PasswordHash() string {
	return creds.GenerateHash(creds.Password)
}

func (creds *Credentials) ValidatePasswordHash(pwdHash string) (bool, error) {
	if pwdHash == creds.PasswordHash() {
		return true, nil
	} else {
		return false, errors.New("Invalid password")
	}
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

// FetchUser gets the user info from the database
func (creds *Credentials) FetchUser() (map[string]interface{}, error) {
	couch := NewCouch(creds.Backend.Server, creds.Backend.UserDB)
	doc, err := couch.Get(creds.Username)

	if err != nil {
		err = errors.New("Error retrieving user info")
	}

	return doc, err
}

// ResolveGroupsToSystems checks the group info for the user and translates it into a
// a list of systems that user has access to with the access rights they have on that system
func (creds *Credentials) ResolveGroupsToSystems(groups []interface{}) []interface{} {
	couch := NewCouch(creds.Backend.Server, creds.Backend.GroupDB)
	docs, err := couch.GetMultiple(groups)

	if err != nil {
		log.Println("Error resolving groups: ", err)
	}

	var systems []interface{}

	if err == nil {
		for _, doc := range docs {
			if systemList, exists := doc.(map[string]interface{})["systems"]; exists {
				systems = systemList.([]interface{})
			}
		}
	}

	return systems
}
