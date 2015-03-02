package gouncer

import (
	"bytes"
	"encoding/json"
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
	defer response.Body.Close() // Close the response body on return

	var doc = make(map[string]interface{})
	if err == nil {
		doc, err = couch.parseResponse(response.Body)
	}

	return doc, err
}

// GetMultiple retrieves multiple documents through a CouchDB bulk request
func (couch *CouchDB) GetMultiple(ids interface{}) ([]interface{}, error) {
	body, err := couch.generateBulkBody(ids)

	response, err := http.Post(couch.bulkUrl(), "application/json", bytes.NewReader(body))
	defer response.Body.Close() // Close the response body on return

	if err == nil {
		return couch.parseBulkResponse(response.Body)
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
			docs = append(docs, row.(map[string]interface{})["doc"])
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