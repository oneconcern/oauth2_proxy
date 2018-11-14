package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"
)

type Server struct {
	Handler http.Handler
	Opts    *Options
}

func (s *Server) ListenAndServe() {
	if s.Opts.TLSKeyFile != "" || s.Opts.TLSCertFile != "" {
		s.ServeHTTPS()
	} else {
		s.ServeHTTP()
	}
}

func (s *Server) ServeHTTP() {
	httpAddress := s.Opts.HttpAddress
	scheme := ""

	i := strings.Index(httpAddress, "://")
	if i > -1 {
		scheme = httpAddress[0:i]
	}

	var networkType string
	switch scheme {
	case "", "http":
		networkType = "tcp"
	default:
		networkType = scheme
	}

	slice := strings.SplitN(httpAddress, "//", 2)
	listenAddr := slice[len(slice)-1]

	listener, err := net.Listen(networkType, listenAddr)
	if err != nil {
		log.Fatalf("FATAL: listen (%s, %s) failed - %s", networkType, listenAddr, err)
	}
	log.Printf("HTTP: listening on %s", listenAddr)

	server := &http.Server{Handler: s.Handler}
	err = server.Serve(listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: http.Serve() - %s", err)
	}

	log.Printf("HTTP: closing %s", listener.Addr())
}

func (s *Server) ServeHTTPS() {
	addr := s.Opts.HttpsAddress
	// Inspired by https://blog.bracebin.com/achieving-perfect-ssl-labs-score-with-go
	config := &tls.Config{
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have assembly implementations
		// https://github.com/golang/go/tree/master/src/crypto/elliptic
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		NextProtos: []string{"http/1.1", "h2"},
		// https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Rule_-_Only_Support_Strong_Protocols
		MinVersion: tls.VersionTLS12,
		// Use modern tls mode https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
		// See security linter code: https://github.com/securego/gosec/blob/master/rules/tls_config.go#L11
		// These ciphersuites support Forward Secrecy: https://en.wikipedia.org/wiki/Forward_secrecy
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(s.Opts.TLSCertFile, s.Opts.TLSKeyFile)
	if err != nil {
		log.Fatalf("FATAL: loading tls config (%s, %s) failed - %s", s.Opts.TLSCertFile, s.Opts.TLSKeyFile, err)
	}
	config.BuildNameToCertificate()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("FATAL: listen (%s) failed - %s", addr, err)
	}
	log.Printf("HTTPS: listening on %s", ln.Addr())

	tlsListener := tls.NewListener(ln, config)
	srv := &http.Server{Handler: s.Handler}
	srv.SetKeepAlivesEnabled(true)
	err = srv.Serve(tlsListener)

	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: https.Serve() - %s", err)
	}

	log.Printf("HTTPS: closing %s", tlsListener.Addr())
}
