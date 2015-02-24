package gouncer

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/RDux/toki"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"
)

type Tokenizer struct {
	GroupDB  string
	Password string
	UserObj  map[string]interface{}
	HashAlg  crypto.Hash
	Secret   string
}

func NewTokenizer(pwd string, usr map[string]interface{}) (*Tokenizer, error) {
	if len(usr) > 0 && pwd != "" {
		return &Tokenizer{
			Password: pwd,
			UserObj:  usr,
		}, nil
	}

	return nil, errors.New("[Authentication error] Missing username or password")
}

func (tokz *Tokenizer) GenerateJWT() (string, error) {
	if tokz.Authorized() {
		jwt := toki.NewJsonWebToken()

		// Add username
		jwt.Claim.Content["user"] = tokz.UserObj["_id"]

		// Add the user description link
		if user, exists := tokz.UserObj["uri"]; exists {
			jwt.Claim.Content["uri"] = user
		}

		// Add the systems
		if sys, exists := tokz.UserObj["systems"]; exists {
			var systems = make(map[string]interface{})

			for system, rights := range tokz.BulkResolveGroupsToSys() {
				systems[system] = rights
			}

			for key, value := range sys.(map[string]interface{}) {
				systems[key] = value
			}

			jwt.Claim.Content["systems"] = systems

		}

		tokz.GenerateSecret()
		jwt.Sign(tokz.Secret)
		return jwt.String()
	}

	return "", errors.New("Invalid password for user: " + tokz.UserObj["_id"].(string))
}

// GenerateSecret uses the password hash the time and a random offset
// to generate a random secret used to sign the token with.
func (tokz *Tokenizer) GenerateSecret() {
	rand.Seed(time.Now().UTC().UnixNano())
	offset := rand.Intn(255)

	pwh := tokz.PasswordHash()
	timeSalt := time.Now().UTC().Add(time.Minute * time.Duration(offset)).Format(time.RFC3339)
	tokz.HashAlg = crypto.SHA1

	tokz.Secret = tokz.GenerateHash(pwh + timeSalt)
}

func (tokz *Tokenizer) BulkResolveGroupsToSys() map[string]interface{} {
	var systems = make(map[string]interface{})

	if groupList, exists := tokz.UserObj["groups"]; exists {
		var bulk = make(map[string]interface{})
		bulk["keys"] = groupList

		if data, err := json.Marshal(bulk); err == nil {
			body := bytes.NewReader(data)
			if response, err := http.Post(tokz.GroupDB+"/_all_docs?include_docs=true", "application/json", body); err == nil {
				groupData, _ := ioutil.ReadAll(response.Body)
				defer response.Body.Close()

				var grpResponse = make(map[string]interface{})
				json.Unmarshal(groupData, &grpResponse)

				// Loop through all the rows in the bulk response
				for _, grp := range grpResponse["rows"].([]interface{}) {
					// Read the systems in the docs
					doc := grp.(map[string]interface{})["doc"]
					doc = doc.(map[string]interface{})["systems"]
					for key, val := range doc.(map[string]interface{}) {
						systems[key] = val
					}
				}
			} else {
				log.Println("couchdb error:", err)
			}
		} else {
			log.Println("Failed to create bulk request", err)
		}
	}

	return systems
}

// Authorized returns true if the hashed input
// password matches that in the userObj
func (tokz *Tokenizer) Authorized() bool {
	return tokz.PasswordHash() == tokz.UserObj["password"].(string)
}

// PasswordHash returns the users password hash. The hasing algorithm is controlled
// by the user object. If no algorithm is set it will use sha512 by default.
// @See tokenizer.ConfigureUserHashAlg()
func (tokz *Tokenizer) PasswordHash() string {
	tokz.ConfigureUserHashAlg()
	return tokz.GenerateHash(tokz.Password)
}

// GenerateHash uses tokenizer.HashAlg to hash string content
func (tokz *Tokenizer) GenerateHash(content string) string {
	alg := tokz.HashAlg.New()
	io.WriteString(alg, content)
	return hex.EncodeToString(alg.Sum(nil))
}

// ConfigureUserHashAlg sets the tokenizers hash algorithm to that in the userObj
func (tokz *Tokenizer) ConfigureUserHashAlg() {
	if hash, exists := tokz.UserObj["hash"]; exists {
		switch hash.(string) {
		case "sha1":
			tokz.HashAlg = crypto.SHA1
		case "sha256":
			tokz.HashAlg = crypto.SHA256
		case "sha384":
			tokz.HashAlg = crypto.SHA384
		default:
			tokz.HashAlg = crypto.SHA512
		}
	}
}
