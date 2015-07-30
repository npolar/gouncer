package gouncer

import (
	"crypto"
	"encoding/json"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	"io/ioutil"
	"net/http"
)

type OneTime struct {
	*Backend
	*Credentials
	*ResponseHandler
	*MailConfig
}

func NewOneTimePassword(h *ResponseHandler) *OneTime {
	o := &OneTime{}
	o.Credentials = &Credentials{}
	o.ResponseHandler = h

	return o
}

func (o *OneTime) RequestPassword() {
	var info RegistrationInfo
	err := o.ExtractOnetimeRequest(&info)

	if err == nil {
		if info.Email != "" {
			o.Username = info.Email
			o.HashAlg = crypto.SHA1
			onetimePass := o.GenerateHash(info.Email + o.CharSalt(128) + o.TimeSalt())
			err = o.Cache.Set(&memcache.Item{Key: info.Email, Value: []byte(onetimePass), Expiration: 1800})

			if err == nil {
				mail := NewMailClient(info.Email, "")
				mail.Backend = o.Backend
				mail.MailConfig = o.MailConfig
				err = mail.OneTimePassword(onetimePass)

				if err == nil {
					o.NewResponse(http.StatusOK, "You should receive an email with your one time password in a few moments")
				}
			}
		} else {
			errors.New("No email address provided")
		}
	}

	if err != nil {
		o.NewError(http.StatusInternalServerError, err.Error())
	}

	o.Respond()
}

func (o *OneTime) ExtractOnetimeRequest(container *RegistrationInfo) error {
	raw, err := ioutil.ReadAll(o.HttpRequest.Body)
	defer o.HttpRequest.Body.Close()

	if err != nil {
		return err
	}

	return json.Unmarshal(raw, container)
}
