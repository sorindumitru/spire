package bundle

import (
	"crypto/tls"
)

func TlsAuth(certFile string, keyFile string) (ServerAuth, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tlsAuth{cert}, nil
}

type tlsAuth struct {
	certificate tls.Certificate
}

func (t *tlsAuth) GetTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{t.certificate},
	}
}
