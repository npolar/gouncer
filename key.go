package gouncer

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type KeyHandler struct {
	Credentials
	*ResponseHandler
	*Backend
}

type KeyRequest struct {
	Key    string `json:"key"`
	System string `json:"system"`
}

type KeyList struct {
	ID    string
	Pairs map[string]string
}

func NewKeyHandler(h *ResponseHandler) *KeyHandler {
	return &KeyHandler{ResponseHandler: h}
}

func (k *KeyHandler) HandleRequest() {
	var kReq = &KeyRequest{}
	err := DecodeJsonRequest(k.HttpRequest.Body, &kReq)

	if err == nil {
		k.ValidateRequest(kReq)
	}

	if err != nil {
		k.NewError(http.StatusUnauthorized, err.Error())
	}
}

func (k *KeyHandler) ValidateRequest(r *KeyRequest) {
	var kList KeyList
	var id, key string

	segs := strings.Split(r.Key, " ")

	if len(segs) == 2 {
		id = segs[0]
		key = segs[1]
	}

	item, err := k.Cache.Get(id)

	if err != nil {
		k.Logger.Println(err)
	}

	if item != nil && item.Value != nil && len(item.Value) > 0 {
		err = json.Unmarshal(item.Value, &kList)
	} else {
		err = fmt.Errorf("Cache Miss: Unable to retrieve keylist")
	}

	if kList.Pairs[key] == "" {
		err = fmt.Errorf("Key Error - Key: %s does not appear in the key list.", key)
	}

	if err == nil {
		rSys, _ := url.Parse(kList.Pairs[key])
		sys, _ := url.Parse(r.System)

		if rSys.Host == sys.Host && k.ExactPathMatch(rSys.Path, sys.Path) || k.WildcardPathMatch(rSys.Path, sys.Path) {
			k.Response.Status = http.StatusOK
			k.Response.AccessRights = []string{"read"}

		} else {
			k.NewError(http.StatusUnauthorized, "Key not valid for system")
		}
	}

	if err != nil {
		log.Println(err)
		k.NewError(http.StatusUnauthorized, err.Error())
	}
}

// ExactPathMatch checks if the two paths are the same
func (k *KeyHandler) ExactPathMatch(pathA string, pathB string) bool {
	return pathA == pathB
}

// WildcardPathMatch checks if a path partially matches and ends in a wildcard
func (k *KeyHandler) WildcardPathMatch(pathA string, pathB string) bool {
	segsA := strings.Split(pathA, "/")
	segsB := strings.Split(pathB, "/")

	match := true

	for i, seg := range segsA {
		if i > (len(segsB) - 1) {
			return false
		}

		if segsB[i] != seg && seg != "*" {
			match = false
		}
	}

	return match
}
