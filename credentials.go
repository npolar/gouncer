package gouncer

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/npolar/toki"
)

const (
	basicPattern  = "(?i)^Basic\\s([a-zA-Z0-9-_=]+)$"
	bearerPattern = "(?i)^Bearer\\s([a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+)$"
)

var sysRegex = regexp.MustCompile(`^http(?:s)?\://(.[^/]+)/(.*[^\*]/?)?(\*)?$`)

type Credentials struct {
	Username string
	Password string
	Salt     string
	Token    string
	Obj      *CacheObj
	HashAlg  crypto.Hash
	Secret   string
	*Backend
	Jwt      *toki.JsonWebToken
	UserInfo map[string]interface{}
}

type CacheObj struct {
	Secret string
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

		if err == nil {
			if len(segs[0]) > 0 && len(segs[1]) > 0 {
				creds.Username = strings.ToLower(segs[0])
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
	creds.Secret = creds.GenerateHash(creds.PasswordHash() + creds.TimeSalt() + creds.CharSalt(64))
}

func (creds *Credentials) TimeSalt() string {
	rand.Seed(time.Now().UTC().UnixNano())
	offset := rand.Intn(100000)

	return time.Now().UTC().Add(time.Minute * time.Duration(offset)).Format(time.RFC3339Nano)
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
	return creds.GenerateHash(creds.Password + creds.Salt)
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

func (creds *Credentials) GenerateUserKey() string {
	summer := crypto.MD5.New()
	io.Copy(summer, bytes.NewReader([]byte(creds.Username)))
	return hex.EncodeToString(summer.Sum(nil))
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
	couch := NewCouch(creds.Couchdb, creds.Userdb)
	doc, err := couch.Get(creds.Username)

	if err != nil {
		err = errors.New("Error retrieving user info")
	}

	return doc, err
}

// ResolveGroupsToSystems checks the group info for the user and translates it into a
// a list of systems that user has access to with the access rights they have on that system
func (creds *Credentials) ResolveGroupsToSystems(groups []interface{}) []interface{} {
	couch := NewCouch(creds.Couchdb, creds.Groupdb)
	docs, err := couch.GetMultiple(groups)

	if err != nil {
		creds.Logger.Println("Error resolving groups: ", err)
	}

	var systems []interface{}

	if err == nil {
		for _, doc := range docs {
			if systemList, exists := doc.(map[string]interface{})["systems"]; exists {
				for _, s := range systemList.([]interface{}) {
					systems = append(systems, s)
				}
			}
		}
	}

	return systems
}

// ValidCredentials returns true if the token or basic auth info provided is valid
func (creds *Credentials) ValidCredentials() (bool, error) {
	if creds.Token == "" && creds.Password != "" {
		return creds.ValidBasicAuth()
	} else {
		return creds.ValidToken()
	}
}

func (creds *Credentials) ValidBasicAuth() (bool, error) {
	userInfo, err := creds.FetchUser()

	if err == nil {
		// Set the UserInfo to the retrieved user doc
		creds.UserInfo = userInfo

		if userInfo["active"] == nil {
			return false, errors.New("Invalid user object. Missing 'active' key.")
		}

		if userInfo["active"].(bool) == true {
			var valid bool

			if userInfo["hash"] != nil && userInfo["salt"] != nil && userInfo["password"] != nil {
				creds.ResolveHashAlg(userInfo["hash"].(string))
				creds.Salt = userInfo["salt"].(string)

				valid, err = creds.ValidatePasswordHash(userInfo["password"].(string))
			} else {
				valid = false
			}

			// If the regular password isn't valid check for a cached one time pass
			if !valid {
				item, cerr := creds.Cache.Get(creds.Username)
				err = cerr

				if err == nil {
					if creds.Password == string(item.Value) {
						return true, err
					} else {
						return false, errors.New("Invalid password")
					}
				}

				// if the cache misses we'll assume you wrote in a wrong password
				err = errors.New("Invalid password")
			}

			return valid, err
		} else {
			err = errors.New("This account has been disabled. Please contact the administrator for more info.")
		}
	}

	return false, err
}

func (creds *Credentials) ValidToken() (bool, error) {
	err := creds.parseToken()

	if err == nil {
		creds.Username = creds.Jwt.Claim.Content["email"].(string)
		userInfo, uerr := creds.FetchUser() // load the user info for token generation purposes
		err = uerr

		if err == nil {
			creds.UserInfo = userInfo

			item, cerr := creds.Cache.Get(creds.Username)
			err = cerr

			if err == nil {
				err = creds.decodeCache(item.Value)

				if err == nil {
					return creds.Jwt.Valid(creds.Obj.Secret)
				}
			}
		}
	}

	return false, err
}

func (creds *Credentials) CacheKeyList(kl *KeyList, exp int32) {
	l, err := json.Marshal(kl)

	if err != nil {
		creds.Logger.Println("KEY LIST ENCODING:", err)
	}

	err = creds.CacheCredentials(kl.ID, l, exp)

	if err != nil {
		creds.Logger.Println("KEY CACHE:", err)
	}
}

func (creds *Credentials) CacheCredentials(k string, v []byte, exp int32) error {
	return creds.Cache.Set(&memcache.Item{Key: k, Value: v, Expiration: exp})
}

func (creds *Credentials) parseToken() error {
	creds.Jwt = toki.NewJsonWebToken()
	err := creds.Jwt.Parse(creds.Token)
	return err
}

func (creds *Credentials) decodeCache(cacheObj []byte) error {
	return json.Unmarshal(cacheObj, &creds.Obj)
}
