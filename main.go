package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/bibaroc/wingman/pkg/logger"
)

// CGO_ENABLED=0 go build -trimpath -a -gcflags='-e -l' -ldflags='-w -s -extldflags "-static"' -o bin/auth
// strip bin/auth
func authentication() func(w http.ResponseWriter, req *http.Request) {
	l := logger.NewLogger(logger.INFO, os.Stdout, logger.WithCallerInfo)
	users := map[string]string{
		"administrator":   "administrator_password",
		"authorized_user": "authorized_user_password",
	}
	realm := os.Getenv("AUTH_REALM")
	return func(w http.ResponseWriter, req *http.Request) {
		username, password, basicAuthOK := req.BasicAuth()
		if !basicAuthOK {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, realm))
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}
		knownPassword, userRegistered := users[username]
		if !userRegistered {
			l.Warnf("Failed login as unregistered user=%s\n", username)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}
		if password != knownPassword {
			l.Warnf("Failed login as user=%s\n", username)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(nil)
	}
}

func requestLogging(
	next func(w http.ResponseWriter, req *http.Request),
) func(w http.ResponseWriter, req *http.Request) {
	l := logger.NewLogger(logger.INFO, os.Stdout, logger.WithCallerInfo)

	return func(w http.ResponseWriter, req *http.Request) {
		header := req.Header
		username, _, _ := req.BasicAuth()
		wrapper := responseWriter{ResponseWriter: w}
		next(&wrapper, req)
		l.Infof("%s -> %s, %s, %s, username=%s, code=%d\n",
			header.Get("X-Real-IP"), header.Get("X-Forwarded-For"), req.Method, header.Get("X-Original-URI"), username, wrapper.status)
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.status = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func main() {
	l := logger.NewLogger(logger.INFO, os.Stdout, logger.WithCallerInfo)

	err := http.ListenAndServeTLS(
		os.Getenv("AUTH_ADDR"),
		os.Getenv("AUTH_TLS_CRT"),
		os.Getenv("AUTH_TLS_KEY"),
		http.HandlerFunc(requestLogging(authentication())))
	l.Fatal(err)
}
