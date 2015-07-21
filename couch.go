package gouncer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	bulk_option = "/_all_docs?include_docs=true"
)

type CouchDB struct {
	Server   string
	Database string
}

// NewCouch initializes a CouchDB instance and returns the pointer
func NewCouch(server string, database string) *CouchDB {
	return &CouchDB{
		Server:   server,
		Database: database,
	}
}

// Get retrieves a single document from CouchDB based on the provided id
func (couch *CouchDB) Get(id string) (map[string]interface{}, error) {
	response, err := http.Get(couch.url() + "/" + id)

	var doc = make(map[string]interface{})

	if err == nil {
		defer response.Body.Close() // Close the response body on return

		if response.StatusCode != 200 {
			return doc, errors.New(response.Status)
		}

		doc, err = couch.parseResponse(response.Body)
	}

	return doc, err
}

// GetMultiple retrieves multiple documents through a CouchDB bulk request
func (couch *CouchDB) GetMultiple(ids interface{}) ([]interface{}, error) {
	body, err := couch.generateBulkBody(ids)

	response, err := http.Post(couch.bulkUrl(), "application/json", bytes.NewReader(body))

	if err == nil {
		defer response.Body.Close() // Close the response body on return
		return couch.parseBulkResponse(response.Body)
	}

	return nil, err
}

// Post posts a single document to couchdb
func (couch *CouchDB) Post(document []byte) (map[string]interface{}, error) {
	response, err := http.Post(couch.url(), "application/json", bytes.NewReader(document))

	if err == nil {
		defer response.Body.Close() // Close the response body on return
		return couch.parseResponse(response.Body)
	}

	return nil, err
}

func (couch *CouchDB) Delete(id string) (map[string]interface{}, error) {
	var err error
	doc, getErr := couch.Get(id)
	err = getErr

	if err == nil {
		rev := doc["_rev"].(string)
		if req, reqErr := http.NewRequest("DELETE", couch.url()+"/"+id+"?rev="+rev, nil); reqErr == nil {
			response, respErr := http.DefaultClient.Do(req)
			err = respErr

			if err == nil {
				return couch.parseResponse(response.Body)
			}
		} else {
			err = reqErr
		}
	}

	return nil, err
}

// generateBulkBody generates the CouchDB bulk body. {"keys":["id1",...,"idn"]}
func (couch *CouchDB) generateBulkBody(ids interface{}) ([]byte, error) {
	var bulk = make(map[string]interface{})
	bulk["keys"] = ids

	return json.Marshal(bulk)
}

// ParseResponse reads the couchDB response and returns the document  or an error
func (couch *CouchDB) parseResponse(body io.ReadCloser) (map[string]interface{}, error) {
	var doc = make(map[string]interface{})
	data, err := ioutil.ReadAll(body)

	if err == nil {
		err = json.Unmarshal(data, &doc)
	}

	return doc, err
}

// parseBulkResponse reads the CouchDB bulk response and strips away the wrappers.
// The result is a []interface{} containing the body for each document retrieved
func (couch *CouchDB) parseBulkResponse(body io.ReadCloser) ([]interface{}, error) {
	var bulk = make(map[string]interface{})
	var docs []interface{}

	bulk, err := couch.parseResponse(body) // Use the regular response parser for initial unmarshaling

	if err == nil {
		// Loop over each row and grab the doc contents
		for _, row := range bulk["rows"].([]interface{}) {
			if doc, exists := row.(map[string]interface{})["doc"]; exists {
				docs = append(docs, doc)
			}
		}
	}

	return docs, err
}

// url builds the url for database access from the configured attributes
func (couch *CouchDB) url() string {
	srv := strings.Trim(couch.Server, "/")
	db := strings.Trim(couch.Database, "/")

	return srv + "/" + db
}

// bulkUrl returns the url for bulk operations on the database
func (couch *CouchDB) bulkUrl() string {
	return couch.url() + bulk_option
}
