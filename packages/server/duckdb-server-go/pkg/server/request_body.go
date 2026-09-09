package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// MaxQueryBodyBytes bounds the JSON command document accepted by POST /.
const MaxQueryBodyBytes int64 = 1 << 20

var errMultipleJSONDocuments = errors.New("multiple JSON documents")

func limitQueryBody(w http.ResponseWriter, r *http.Request) io.ReadCloser {
	return http.MaxBytesReader(w, r.Body, MaxQueryBodyBytes)
}

func decodeQueryBody(body io.Reader, dst any) error {
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return errMultipleJSONDocuments
		}
		return err
	}
	return nil
}

func writeQueryBodyError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "invalid JSON request body", http.StatusBadRequest)
}
