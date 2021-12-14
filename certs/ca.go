package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

// `CA` issues certificates using a CA certificate.
type CA struct {
	Certificate *x509.Certificate
	PublicKey interface{}
	PrivateKey interface{}

	cache *Cache
	group *singleflight.Group
}

// `NewCA` creates an `Issuer` by loading the given CA certificate and private key files.
func NewCA(crt, key string) (Issuer, error) {
	cd, err := load(crt)
	if err != nil {
		return nil, err
	}

	c, err := x509.ParseCertificate(cd.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate from '%v': %v", crt, err)
	}

	kd, err := load(key)
	if err != nil {
		return nil, err
	}

	k, err := x509.ParsePKCS8PrivateKey(kd.Bytes)
	if err != nil {
		if strings.Contains(err.Error(), "use ParseECPrivateKey instead") {
			k, err = x509.ParseECPrivateKey(kd.Bytes)
		} else if strings.Contains(err.Error(), "use ParsePKCS1PrivateKey instead") {
			k, err = x509.ParsePKCS1PrivateKey(kd.Bytes)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to load CA private key from '%v': %v", key, err)
		}
	}

	var pub interface{}
	switch priv := k.(type) {
	case *ecdsa.PrivateKey:
		pub = priv.PublicKey
	case *rsa.PrivateKey:
		pub = priv.PublicKey
	default:
		return nil, fmt.Errorf("unsupported CA private key type in '%v'", key)
	}

	return &CA {
		Certificate: c,
		PublicKey: pub,
		PrivateKey: k,
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

	b, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &priv.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{b},
		PrivateKey: priv,
		Leaf: cert,
	}, nil
}
