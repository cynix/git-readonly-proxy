package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"

	"golang.org/x/sync/singleflight"
)

// `CA` issues certificates using a CA certificate.
type CA struct {
	tls.Certificate

	cache *Cache
	group *singleflight.Group
}

// `NewCA` creates an `Issuer` by loading the given CA certificate and private key files.
func NewCA(crt, key string) (Issuer, error) {
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &CA {
		Certificate: cert,
		cache: NewCache(128),
		group: new(singleflight.Group),
	}, nil
}

func (ca *CA) Issue(domain string) (*tls.Certificate, error) {
	if v, ok := ca.cache.Get(domain); ok {
		cert := v.(*tls.Certificate)

		if cert.Leaf.NotAfter.After(time.Now().Add(1 * time.Minute)) {
			return cert, nil
		}
	}

	v, err, _ := ca.group.Do(domain, func() (interface{}, error) {
		cert, err := ca.issue(domain)
		if err == nil {
			ca.cache.Add(domain, cert)
			log.Printf("issued certificate for %v (expires %v)", domain, cert.Leaf.NotAfter)
		} else {
			log.Printf("could not issue certificate for %v: %v", domain, err)
		}
		return cert, err
	})
	if err != nil {
		return nil, err
	}

	return v.(*tls.Certificate), nil
}

func (ca *CA) issue(domain string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: domain,
			Organization: []string{"Proxy"},
		},
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter: now.Add(366 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{domain},
	}

	b, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate.Leaf, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: append([][]byte{b}, ca.Certificate.Certificate[0:len(ca.Certificate.Certificate)-1]...),
		PrivateKey: key,
		Leaf: cert,
	}, nil
}
