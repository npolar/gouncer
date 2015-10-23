package gouncer

import (
	"crypto"
	"encoding/json"
	"net/http"
)

type Reset struct {
	Credentials
	*ResponseHandler
}

type ResetBody struct {
	Password string
}

func NewResetHandler(h *ResponseHandler) *Reset {
	return &Reset{ResponseHandler: h}
}

func (re *Reset) UserPassword() {
	err := re.ParseAuthHeader(re.HttpRequest.Header.Get("Authorization"))

	if err == nil {
		var rb ResetBody

		if err = DecodeJsonRequest(re.HttpRequest.Body, &rb); err == nil {
			re.handleReset(rb)
		}
	}

	if err != nil {
		re.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (re *Reset) handleReset(rb ResetBody) {
	if rb.Password != "" {
		if re.Token == "" && re.Password != "" {
			re.basicReset(rb)
		} else {
			re.tokenReset(rb)
		}
	} else {
		re.NewError(http.StatusBadRequest, "Please submit a password in the reset request")
	}
}

func (re *Reset) basicReset(rb ResetBody) {
	if valid, err := re.ValidBasicAuth(); valid {
		re.executeReset(rb)
	} else {
		re.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (re *Reset) tokenReset(rb ResetBody) {
	if valid, err := re.ValidToken(); valid {
		re.executeReset(rb)
	} else {
		re.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (re *Reset) executeReset(rb ResetBody) {
	re.HashAlg = crypto.SHA512
	re.Password = rb.Password
	re.Salt = re.CharSalt(64)
	passhash := re.PasswordHash()

	re.UserInfo["hash"] = "sha512"
	re.UserInfo["salt"] = re.Salt
	re.UserInfo["password"] = passhash

	if doc, err := json.Marshal(re.UserInfo); err == nil {
		couch := NewCouch(re.Backend.Couchdb, re.Backend.Userdb)
		if _, err := couch.Post(doc); err == nil {
			re.Response.Status = http.StatusOK
			re.Response.Message = "Your password was successfully updated."
		} else {
			re.NewError(http.StatusInternalServerError, err.Error())
		}
	} else {
		re.NewError(http.StatusInternalServerError, err.Error())
	}
}
