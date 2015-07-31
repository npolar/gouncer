package gouncer

import (
	"net/http"
	"strings"
)

type Confirm struct {
	*Backend
	Handler *ResponseHandler
}

func NewConfirm(h *ResponseHandler) *Confirm {
	return &Confirm{Handler: h}
}

// Registration completes the registration process after the user clicks the confirmation link
func (c *Confirm) Registration() {
	segs := strings.Split(c.Handler.HttpRequest.URL.Path, "/")

	if item, err := c.Backend.Cache.Get(segs[len(segs)-1]); err == nil {
		doc := item.Value

		couch := NewCouch(c.Backend.Couchdb, c.Backend.Userdb)
		if _, err := couch.Post(doc); err == nil {
			// If the user object was correctly saved to the backend we delete the cache entry
			c.Backend.Cache.Delete(segs[len(segs)-1])

			// Respond to the user
			c.Handler.NewResponse(http.StatusOK, "Registration successfull. You can now login with your new account.")
		} else {
			c.Handler.NewError(http.StatusInternalServerError, err.Error())
		}

	} else {
		c.Handler.NewError(http.StatusInternalServerError, err.Error())
	}
}
