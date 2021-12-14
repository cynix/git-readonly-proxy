package certs

import (
	"crypto/tls"
)


// `Issuer` issues certificates on demand.
type Issuer interface {
	Issue(domain string) (*tls.Certificate, error)
}
