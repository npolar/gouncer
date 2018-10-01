package gouncer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type ResponseHandler struct {
	Writer      http.ResponseWriter
	HttpRequest *http.Request
	Response    *Response
	JsonP       bool
}

type Response struct {
	Status       int         `json:"status,omitempty" xml:"Status,attr,omitempty"`
	HttpMessage  string      `json:"http_message,omitempty" xml:"HttpMessage,omitempty"`
	Error        string      `json:"error,omitempty" xml:"Error,omitempty"`
	Message      string      `json:"message,omitempty" xml:"Message,omitempty"`
	Token        string      `json:"token,omitempty" xml:"Token,omitempty"`
	AccessRights interface{} `json:"rights,omitempty" xml:"Access>Right,omitempty"`
	Info         *Info       `json:"info,omitempty" xml:",omitempty"`
}

func NewResponseHandler(w http.ResponseWriter, r *http.Request) *ResponseHandler {
	return &ResponseHandler{
		Response:    &Response{},
		Writer:      w,
		HttpRequest: r,
	}
}

// NewError loads error data into the Response structure
func (resp *ResponseHandler) NewError(status int, err string) {
	resp.Response = &Response{
		Status:      status,
		HttpMessage: http.StatusText(status),
		Error:       err,
	}
}

// NewResponse loads response data into the Response structure
func (resp *ResponseHandler) NewResponse(status int, message string) {
	resp.Response = &Response{
		Status:      status,
		HttpMessage: http.StatusText(status),
		Message:     message,
	}
}

func (h *ResponseHandler) Respond() {
	switch strings.ToLower(h.HttpRequest.Header.Get("Accept")) {
	case "text/plain":
		h.RespondText()
	case "application/xml", "text/xml":
		h.RespondXml()
	default:
		h.RespondJson()
	}
}

func (h *ResponseHandler) RespondText() {
	if h.Response.Error == "" {
		if h.Response.Token != "" {
			fmt.Fprintf(h.Writer, "%v", h.Response.Token)
		} else if h.Response.AccessRights != nil {
			fmt.Fprintf(h.Writer, "%v", h.Response.AccessRights)
		} else {
			fmt.Fprintf(h.Writer, "%+v", h.Response.Info)
		}
	} else {
		h.Writer.WriteHeader(h.Response.Status)
		h.Writer.Write([]byte(h.Response.String()))
	}
}

func (h *ResponseHandler) RespondJson() {
	var body []byte

	h.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	h.Writer.WriteHeader(h.Response.Status)
	body, _ = json.Marshal(h.Response)

	if callback := h.HttpRequest.FormValue("callback"); callback != "" && h.JsonP {
		fmt.Fprintf(h.Writer, "%s(%s)", callback, body)
	} else {
		h.Writer.Write(body)
	}
}

func (h *ResponseHandler) RespondXml() {
	var body []byte

	h.Writer.Header().Set("Content-Type", "application/xml; charset=utf-8")
	h.Writer.WriteHeader(h.Response.Status)
	body, _ = xml.MarshalIndent(h.Response, "", "  ")

	h.Writer.Write(body)
}

// String converts the Response struct to a string
func (r *Response) String() string {
	return strconv.Itoa(r.Status) + " - " + r.HttpMessage + ": [Error]" + r.Error + " [Message]" + r.Message
}
