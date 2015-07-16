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
	Credentials
	Handler *ResponseHandler
	RegistrationInfo
}

type RegistrationInfo struct {
	Email    string   `json:"_id,omitempty"`
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

func (r *Register) Submit() {
	if err := r.parseUserInfo(); err == nil {
		couch := NewCouch(r.Backend.Server, r.Backend.UserDB)
		_, err := couch.Get(r.RegistrationInfo.Email)

		if err != nil {
			if err.Error() == "404 Object Not Found" {
				ip, _ := r.localIP()

				if cache, err := r.cacheRegistrationRequest(); err == nil {
					r.sendConfirmationMail(ip.String(), cache)
					r.Handler.Writer.Write([]byte("In a few moments you will receive a confirmation email at: " + r.RegistrationInfo.Email + ". Please click the link inside to complete your registration."))
				} else {
					r.Handler.NewError(http.StatusInternalServerError, "")
					r.Handler.Respond()
				}
			} else {
				r.Handler.NewError(http.StatusInternalServerError, err.Error())
				r.Handler.Respond()
			}
		} else {
			r.Handler.NewError(http.StatusConflict, "This user already exists")
			r.Handler.Respond()
		}

	} else {
		r.Handler.NewError(http.StatusNotAcceptable, "")
		r.Handler.Respond()
	}

}

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

// cacheRegistrationRequest generates a password has for the password in the request and
// creates a memcache entry before sending the confirmation email pointing to the cached
// reference
func (r *Register) cacheRegistrationRequest() (string, error) {
	r.Credentials.HashAlg = crypto.SHA512
	r.Credentials.Password = r.RegistrationInfo.Password
	passhash := r.Credentials.PasswordHash()

	// Hash the email address and use it as a key
	r.Credentials.HashAlg = crypto.SHA1
	key := r.Credentials.GenerateHash(r.RegistrationInfo.Email)

	// Build the user object
	user := &RegistrationInfo{
		Email:    r.RegistrationInfo.Email,
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

func (r *Register) parseUserInfo() error {
	info, err := ioutil.ReadAll(r.Handler.HttpRequest.Body)

	if err == nil {
		json.Unmarshal(info, &r.RegistrationInfo)
	}

	return err
}

func (r *Register) defaultGroups() []string {
	var groups []string
	return groups
}

func (r *Register) sendConfirmationMail(host string, confirmationID string) {
	var message string
	confirmregxp := regexp.MustCompile("{{confirm}}")
	link := "https://" + host + ":8950/confirm/" + confirmationID

	// Load the mail contents

	if template, err := ioutil.ReadFile("./conf/confirmation.txt"); err == nil {
		message = confirmregxp.ReplaceAllString(string(template), link)
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
