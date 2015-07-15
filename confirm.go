package gouncer

import (
	"log"
	"net/http"
	"strings"
)

type Confirmation struct {
	*Backend
	Handler *ResponseHandler
}

func NewConfirmation(h *ResponseHandler) *Confirmation {
	return &Confirmation{
		Handler: h,
	}
}

func (c *Confirmation) ConfirmRegistration() {
	segs := strings.Split(c.Handler.HttpRequest.URL.Path, "/")
	log.Println(segs[len(segs)-1])

	if item, err := c.Backend.Cache.Get(segs[len(segs)-1]); err == nil {
		doc := item.Value

		couch := NewCouch(c.Backend.Server, c.Backend.UserDB)
		if response, err := couch.Post(doc); err == nil {
			c.Backend.Cache.Delete(segs[len(segs)-1])
			log.Println(response)
			c.Handler.Writer.Write([]byte("Registration successfull. You can now login with your new account."))
		} else {
			c.Handler.NewError(http.StatusInternalServerError, err.Error())
			c.Handler.Respond()
		}

	} else {
		c.Handler.NewError(http.StatusInternalServerError, err.Error())
		c.Handler.Respond()
	}
}
