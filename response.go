package gouncer

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"
)

type ResponseHandler struct {
	Writer      http.ResponseWriter
	HttpRequest *http.Request
	Response    *AuthResponse
	Error       *AuthError
}

type AuthResponse struct {
	Token        string      `json:"token,omitempty" xml:"Token,omitempty"`
	AccessRights interface{} `json:"rights,omitempty" xml:"Access>Right,omitempty"`
}

type AuthError struct {
	Status    int    `json:"status,omitempty" xml:"Status,attr,omitempty"`
	HttpError string `json:"http_error,omitempty" xml:"Error,omitempty"`
	Message   string `json:"message,omitempty" xml:"Message,omitempty"`
}

// NewError loads initial data into the AuthError structure
func (resp *ResponseHandler) NewError(status int, message string) {
	resp.Error = &AuthError{
		Status:    status,
		HttpError: ResolveStatus(status),
		Message:   message,
	}
}

// ResolveStatus returns the defined explanation for the status code
func ResolveStatus(status int) string {
	switch status {
	case http.StatusOK:
		return "OK"
	case http.StatusCreated:
		return "Created"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusBadRequest:
		return "Bad Request"
	case http.StatusInternalServerError:
		return "Internal Server Error"
	default:
		return "Not defined in system"
	}
}

func (h *ResponseHandler) Respond() {
	switch h.HttpRequest.Header.Get("Accept") {
	case "application/json":
		h.RespondJson()
	case "application/xml", "text/xml":
		h.RespondXml()
	default:
		h.RespondText()
	}
}

func (h *ResponseHandler) RespondText() {
	var body []byte
	if h.Error == nil {
		if h.Response.Token != "" {
			body = []byte(h.Response.Token)
		} else {
			var rights []string
			for _, val := range h.Response.AccessRights.([]interface{}) {
				rights = append(rights, val.(string))
			}
			body = []byte(strings.Join(rights, ","))
		}
	} else {
		h.Writer.WriteHeader(h.Error.Status)
		body = []byte(h.Error.String())
	}

	h.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	h.Writer.Write(body)
}

func (h *ResponseHandler) RespondJson() {
	var body []byte
	if h.Error == nil {
		body, _ = json.Marshal(h.Response)
	} else {
		h.Writer.WriteHeader(h.Error.Status)
		body, _ = json.Marshal(h.Error)
	}
	h.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	h.Writer.Write(body)
}

func (h *ResponseHandler) RespondXml() {
	var body []byte
	if h.Error == nil {
		body, _ = xml.MarshalIndent(h.Response, "", "  ")
	} else {
		h.Writer.WriteHeader(h.Error.Status)
		body, _ = xml.MarshalIndent(h.Error, "", "  ")
	}
	h.Writer.Header().Set("Content-Type", "application/xml; charset=utf-8")
	h.Writer.Write(body)
}

// String converts the AuthError struct to a string
func (authErr *AuthError) String() string {
	return strconv.Itoa(authErr.Status) + " - " + authErr.HttpError + ": " + authErr.Message
}
