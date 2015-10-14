package gouncer

import (
	"net/http"
	"regexp"
)

const (
	sicasPattern = "(?i)^Sicas\\s+([a-z0-9+-_=]+)$"
)

func (creds *Credentials) ParseSicasAuth(authHeader string) (bool, []string) {
	rxp := regexp.MustCompile(sicasPattern)

	// Check if Authorization header matches
	if match := rxp.FindStringSubmatch(authHeader); match != nil {
		// Base64Url decode matching string
		if decoded, err := creds.DecodeBase64(match[1]); err == nil {
			// Split decoded string at colon
			if segs, err := creds.SplitBasicAuth(decoded); err == nil {
				return true, segs
			}
		}
	}

	return false, nil
}

type SicasResponse struct {
	Status  int
	Reason  string
	Success bool
}

func (creds *Credentials) sicasValidate(host string, uuid string, captcha string) (SicasResponse, error) {
	httpRes, err := http.Get(host + "/validate/" + uuid + "?string=" + captcha)
	var jsonDoc SicasResponse

	if err == nil {
		err = DecodeJsonRequest(httpRes.Body, &jsonDoc)
	}

	return jsonDoc, err
}
