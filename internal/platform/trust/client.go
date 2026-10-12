// Package trust constructs explicit, process-local TLS clients for sandbox
// endpoints without changing the host trust store.
package trust

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// NewHTTPClientFromCAFile trusts only the PEM certificate authorities in path.
// Redirects are refused so control requests cannot migrate to another origin.
func NewHTTPClientFromCAFile(path string) (*http.Client, error) {
	if path == "" {
		return nil, errors.New("CA file is required")
	}

	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load control CA: %w", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("control CA file contains no certificates")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS12,
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
