package gouncer

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bradfitz/gomemcache/memcache"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"regexp"
)

type Register struct {
	*Core
	*Confirmation
	Credentials
	Handler *ResponseHandler
	RegistrationInfo
	Groups map[string]Registration
}

type RegistrationInfo struct {
	Email    string   `json:"_id,omitempty"`
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
		couch := NewCouch(r.Backend.Couchdb, r.Backend.Userdb)
		_, err := couch.Get(r.RegistrationInfo.Email)

		if err != nil {
			if err.Error() == "404 Object Not Found" {

				if cache, err := r.cacheRegistrationRequest(); err == nil {
					r.sendConfirmationMail(r.resolveHost(), cache)
					r.Handler.NewResponse(http.StatusOK, "In a few moments you will receive a confirmation email at: "+r.RegistrationInfo.Email+". To complete the registration click the link inside.")
				} else {
					r.Handler.NewError(http.StatusInternalServerError, err.Error())
				}
			} else {
				r.Handler.NewError(http.StatusInternalServerError, err.Error())
			}
		} else {
			r.Handler.NewError(http.StatusConflict, "This user already exists")
		}

	} else {
		r.Handler.NewError(http.StatusNotAcceptable, "")
	}

	r.Handler.Respond()
}

// localIP tries to resolve the local IP of the server
func (r *Register) localIP() (net.IP, error) {
	tt, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, t := range tt {
		aa, err := t.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range aa {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil || v4[0] == 127 { // loopback address
				continue
			}
			return v4, nil
		}
	}
	return nil, errors.New("cannot find local IP address")
}

func (r *Register) resolveHost() string {
	// Set host to localhost as default
	host := "localhost"

	// Check if an external hostname was provided. if so use this instead
	if r.Core.Hostname != "" {
		host = r.Core.Hostname
	} else {
		// If no hostname is configured use the IP address
		if ip, err := r.localIP(); err == nil {
			host = ip.String()
		}
	}

	return host
}

// cacheRegistrationRequest generates a password has for the password in the request and
// creates a memcache entry before sending the confirmation email pointing to the cached
// reference
func (r *Register) cacheRegistrationRequest() (string, error) {
	r.Credentials.HashAlg = crypto.SHA512
	r.Credentials.Password = r.RegistrationInfo.Password
	passhash := r.Credentials.PasswordHash()

	// Hash the email address and use it as a key
	r.Credentials.HashAlg = crypto.SHA1
	key := r.Credentials.GenerateHash(r.RegistrationInfo.Email + r.TimeSalt() + r.CharSalt(32))

	// Build the user object
	user := &RegistrationInfo{
		Email:    r.RegistrationInfo.Email,
		Name:     r.RegistrationInfo.Name,
		Password: passhash,
		Active:   true,
		Groups:   r.defaultGroups(),
		Hash:     "sha512",
	}

	userDoc, _ := json.Marshal(user)

	// Create a new cache entry for the registration request
	err := r.Backend.Cache.Set(&memcache.Item{Key: key, Value: userDoc, Expiration: 1200})
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

// defaultGroups tries to assing default group settings to users based on the e-mail domain.
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

// sendConfirmationMail generates an smtp request with a confirmation email to the user
func (r *Register) sendConfirmationMail(host string, confirmationID string) {
	var message string
	confirmregxp := regexp.MustCompile("{{confirm}}")
	link := "https://" + host + r.Core.Port + "/confirm/" + confirmationID

	// Load the mail contents

	if r.Confirmation.Message != "" {
		message = "Subject:" + r.Confirmation.Subject + "\n\n"
		message += confirmregxp.ReplaceAllString(r.Confirmation.Message, link)
	} else { // When no message is configured use a generic registration message
		message = "Subject:Account Registration\n\nThank you for registering.\n\nTo complete your registration please click the following link: " + link + "\n\nIf you did not try to register an account with us feel free to ignore or delete this message."
	}

	// Connect to the remote SMTP server specified through the commandline.
	c, err := smtp.Dial(r.Backend.Smtp)
	if err != nil {
		log.Println(err)
	}

	// Set the sender
	if err := c.Mail("data@npolar.no"); err != nil {
		log.Println(err)
	}

	// Set the recipient
	if err := c.Rcpt(r.RegistrationInfo.Email); err != nil {
		log.Println(err)
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Println(err)
	}
	_, err = fmt.Fprintf(wc, message)
	if err != nil {
		log.Println(err)
	}
	err = wc.Close()
	if err != nil {
		log.Println(err)
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		log.Println(err)
	}
}
