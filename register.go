package gouncer

import (
	"crypto"
	"encoding/json"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	"io/ioutil"
	"net/http"
	"regexp"
)

type Register struct {
	*Core
	*MailConfig
	Credentials
	Handler *ResponseHandler
	RegistrationInfo
	Groups map[string]Registration
}

// Registration groups
type Registration struct {
	Domain string
	Groups []string
}

type RegistrationInfo struct {
	Id       string   `json:"_id,omitempty"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Password string   `json:"password,omitempty"`
	Active   bool     `json:"active,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Hash     string   `json:"hash,omitempty"`
}

func NewRegistration(h *ResponseHandler) *Register {
	return &Register{
		Handler: h,
	}
}

// Submit triggers the registration sequence.
func (r *Register) Submit() {
	if err := r.parseUserInfo(); err == nil {
		r.processRegistration()
	} else {
		r.Handler.NewError(http.StatusNotAcceptable, err.Error())
	}

	r.Handler.Respond()
}

// Cancel triggers the account cancellation sequence
func (r *Register) Cancel() {
	if err := r.ParseAuthHeader(r.Handler.HttpRequest.Header.Get("Authorization")); err == nil {
		r.processCancellation()
	} else {
		r.Handler.NewError(http.StatusUnauthorized, "")
	}

	r.Handler.Respond()
}

func (r *Register) processRegistration() {
	couch := NewCouch(r.Backend.Couchdb, r.Backend.Userdb)
	_, err := couch.Get(r.RegistrationInfo.Email)

	if err != nil {
		if err.Error() == "404 Object Not Found" {
			id, rerr := r.cacheRegistrationRequest()
			err = rerr

			if err == nil {
				mail := NewMailClient(r.RegistrationInfo.Email, id)
				mail.MailConfig = r.MailConfig
				mail.Backend = r.Backend
				mail.Core = r.Core

				err = mail.Confirmation()

				if err == nil {
					r.Handler.NewResponse(http.StatusOK, "In a few moments you will receive a confirmation email at: "+r.RegistrationInfo.Email+". To complete the registration click the link inside.")
				}
			}
		}

		if err != nil {
			r.Handler.NewError(http.StatusInternalServerError, err.Error())
		}
	} else {
		r.Handler.NewError(http.StatusConflict, "This uers already exists.")
	}
}

func (r *Register) processCancellation() {
	var err error

	valid, cerr := r.ValidCredentials()
	err = cerr

	if valid {
		err = r.cancelAccount()
	}

	if err != nil {
		r.Handler.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (r *Register) cancelAccount() error {
	var err error

	r.Credentials.HashAlg = crypto.SHA1
	id := r.Credentials.GenerateHash(r.Username + r.TimeSalt() + r.CharSalt(32))

	err = r.Backend.Cache.Set(&memcache.Item{Key: id, Value: []byte(r.Username), Expiration: r.LinkTimeout})

	if err == nil {
		mail := NewMailClient(r.Username, id)
		mail.MailConfig = r.MailConfig
		mail.Backend = r.Backend
		mail.Core = r.Core
		if mErr := mail.Cancellation(); mErr == nil {
			r.Handler.NewResponse(http.StatusOK, "In a few moments you will receive a confirmation email at: "+r.Username+". To complete the cancellation click the link inside.")
		} else {
			err = mErr
		}
	}

	return err
}

// cacheRegistrationRequest generates a password has for the password in the request and
// creates a memcache entry before sending the confirmation email pointing to the cached
// reference
func (r *Register) cacheRegistrationRequest() (string, error) {
	if r.RegistrationInfo.Email == "" {
		return "", errors.New("[Registration Error] Missing email")
	}

	if r.RegistrationInfo.Password == "" {
		return "", errors.New("[Registration Error] Missing password")
	}

	r.Credentials.HashAlg = crypto.SHA512
	r.Credentials.Password = r.RegistrationInfo.Password
	passhash := r.Credentials.PasswordHash()

	// Hash the email address and use it as a key
	r.Credentials.HashAlg = crypto.SHA1
	key := r.Credentials.GenerateHash(r.RegistrationInfo.Email + r.TimeSalt() + r.CharSalt(32))

	// Build the user object
	user := &RegistrationInfo{
		Id:       r.RegistrationInfo.Email, // Set the Email address as the id
		Email:    r.RegistrationInfo.Email,
		Name:     r.RegistrationInfo.Name,
		Password: passhash,
		Active:   true,
		Groups:   r.defaultGroups(),
		Hash:     "sha512",
	}

	userDoc, _ := json.Marshal(user)

	// Create a new cache entry for the registration request
	err := r.Backend.Cache.Set(&memcache.Item{Key: key, Value: userDoc, Expiration: r.LinkTimeout})
	return key, err
}

// parseUserInfo unmarshals the registration body into the RegistrationInfo struct
func (r *Register) parseUserInfo() error {
	info, err := ioutil.ReadAll(r.Handler.HttpRequest.Body)

	if err == nil {
		json.Unmarshal(info, &r.RegistrationInfo)
	}

	return err
}

// defaultGroups tries to assing default group settings to users based on the email domain.
func (r *Register) defaultGroups() []string {
	mailregxp := regexp.MustCompile(".*@(.*\\.[a-zA-Z]{2,3})")
	matches := mailregxp.FindStringSubmatch(r.RegistrationInfo.Email)

	// Check if the users email domain matches any of the configured group domains
	for _, grp := range r.Groups {
		if grp.Domain == matches[1] {
			return grp.Groups
		}
	}

	// If none of the group domains matched return the default group
	return r.Groups["default"].Groups
}
