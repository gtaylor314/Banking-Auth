package app

import (
	"encoding/json"
	"net/http"

	"github.com/gtaylor314/Banking-Auth/dto"
	"github.com/gtaylor314/Banking-Auth/service"

	"github.com/gtaylor314/Banking-Lib/errs"
	"github.com/gtaylor314/Banking-Lib/logger"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// creating Login Request object to populate from json body
	var req dto.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		logger.Error("error while decoding json body for login request: " + err.Error())
		writeResponse(w, http.StatusBadRequest, errs.AppError{Message: err.Error()})
		return
	}
	// Login() takes our Login Request object and returns a Login Response object, which holds our access token, and an error
	token, appErr := h.service.Login(req)
	if appErr != nil {
		writeResponse(w, appErr.Code, appErr.MessageOnly())
		return
	}
	writeResponse(w, http.StatusOK, *token)
}

func (h AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	// create urlParams to populate from http.Request
	urlParams := make(map[string]string)
	// for-range across the URL Parameters in the http.Request and for each key, populate urlParams with the key and the
	// first value associated with that key
	// (Query returns all values (map[string][]string) but Get returns the first value only (string))
	for key := range r.URL.Query() {
		urlParams[key] = r.URL.Query().Get(key)
	}
	// if the access token is missing
	if urlParams["token"] == "" {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse("missing access token"))
		return
	}
	// otherwise, the access token has been provided
	appErr := h.service.Verify(urlParams)
	if appErr != nil {
		writeResponse(w, appErr.Code, notAuthorizedResponse(appErr.Message))
		return
	}
	writeResponse(w, http.StatusOK, authorizedResponse())
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	// set our response header
	w.Header().Add("Content-Type", "application/json")
	// set the http status code for the header
	w.WriteHeader(code)
	// encode data in the json format and write to the stream
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		panic(err)
	}
}

func notAuthorizedResponse(message string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      message,
	}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{
		"isAuthorized": true,
	}
}
