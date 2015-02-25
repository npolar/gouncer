package gouncer

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
)

const (
	basicPattern  = "(?i)^Basic\\s([a-zA-Z0-9-_=]+)$"
	bearerPattern = "(?i)^Bearer\\s([a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+)$"
)

type Credentials struct {
	Username string
	Password string
	Token    string
}

func (creds *Credentials) ParseAuthHeader(value string) error {
	if basicAuth, rxp := creds.BasicAuth(value); basicAuth {
		matches := rxp.FindAllStringSubmatch(value, -1)
		return creds.ParseBasicAuth(matches[0][1])
	} else if bearerAuth, rxp := creds.BearerToken(value); bearerAuth {
		matches := rxp.FindAllStringSubmatch(value, -1)
		creds.Token = matches[0][1]
		return nil
	}

	return errors.New("Unsupported authorization method")
}

func (creds *Credentials) BasicAuth(authHeader string) (bool, *regexp.Regexp) {
	rxp := regexp.MustCompile(basicPattern)
	return rxp.MatchString(authHeader), rxp
}

func (creds *Credentials) BearerToken(authHeader string) (bool, *regexp.Regexp) {
	rxp := regexp.MustCompile(bearerPattern)
	return rxp.MatchString(authHeader), rxp
}

func (creds *Credentials) ParseBasicAuth(basicAuth string) error {
	if credString, err := creds.DecodeBase64(basicAuth); err == nil {
		segs, err := creds.SplitBasicAuth(credString)

		if err != nil {
			return err
		}

		creds.Username = segs[0]
		creds.Password = segs[1]

		return nil
	} else {
		return err
	}
}

func (creds *Credentials) SplitBasicAuth(content string) ([]string, error) {
	if strings.Contains(content, ":") {
		return strings.Split(content, ":"), nil
	} else {
		return []string{""}, errors.New("Malformed credentials payload")
	}
}

func (creds *Credentials) DecodeBase64(content string) (string, error) {
	if raw, err := base64.StdEncoding.DecodeString(content); err == nil {
		return string(raw), nil
	} else {
		return "", err
	}
}
