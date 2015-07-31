package gouncer

import (
	"net/http"
	"strings"
)

type Cancel struct {
	*Backend
	Handler *ResponseHandler
}

func NewCancellation(h *ResponseHandler) *Cancel {
	return &Cancel{Handler: h}
}

// Registration completes the registration process after the user clicks the confirmation link
func (c *Cancel) Confirm() {
	segs := strings.Split(c.Handler.HttpRequest.URL.Path, "/")

	if item, err := c.Backend.Cache.Get(segs[len(segs)-1]); err == nil {
		key := string(item.Value)

		couch := NewCouch(c.Backend.Couchdb, c.Backend.Userdb)
		if _, err := couch.Delete(key); err == nil {
			// If the user object is correctly delete we wipe the cache entry for the cancellation request and any token still in the cache
			c.Backend.Cache.Delete(segs[len(segs)-1])
			c.Backend.Cache.Delete(key)

			// Respond to the user
			c.Handler.NewResponse(http.StatusOK, "Cancellation successfull.")
		} else {
			c.Handler.NewError(http.StatusInternalServerError, err.Error())
		}

	} else {
		c.Handler.NewError(http.StatusInternalServerError, err.Error())
	}
	c.Handler.Respond()
}
