package gouncer

import (
	"crypto"
	"errors"
	"net/http"
)

type OneTime struct {
	*Credentials
	*ResponseHandler
	*MailConfig
}

func NewOneTimePassword(h *ResponseHandler) *OneTime {
	return &OneTime{
		Credentials:     &Credentials{},
		ResponseHandler: h,
	}
}

func (o *OneTime) RequestPassword() {
	var info RegistrationInfo
	err := DecodeJsonRequest(o.HttpRequest.Body, &info)

	if err == nil {
		pwd, perr := o.generateOneTimePassword(info.Email)
		err = perr

		if err == nil {
			err = o.mailPassword(pwd)
		}
	}

	if err != nil {
		o.NewError(http.StatusInternalServerError, err.Error())
	}
}

func (o *OneTime) generateOneTimePassword(user string) (string, error) {
	if user != "" {
		var pwd string
		o.Username = user
		o.HashAlg = crypto.SHA1

		_, err := o.FetchUser()

		if err == nil {
			pwd = o.GenerateHash(user + o.CharSalt(128) + o.TimeSalt())
			err = o.CacheCredentials(user, []byte(pwd), 1800)
		} else {
			err = errors.New("User Not found")
		}

		return pwd, err
	}

	return "", errors.New("No email address provided")
}

func (o *OneTime) mailPassword(pwd string) error {
	mail := NewMailClient(o.Username, "")
	mail.Backend = o.Backend
	mail.MailConfig = o.MailConfig
	err := mail.OneTimePassword(pwd)

	if err == nil {
		o.NewResponse(http.StatusOK, "You should receive an email with your one time password in a few moments")
	}

	return err
}
