package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"path"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

// `Loader` reads pre-issued certificates from a directory.
type Loader struct {
	Dir string

	cache *Cache
	group *singleflight.Group
}

// `NewLoader` creates an `Issuer` using pre-issued certificates from a directory.
func NewLoader(dir string) (Issuer, error) {
	return &Loader{
		Dir: dir,
		cache: NewCache(128),
		group: new(singleflight.Group),
	}, nil
}

func (l *Loader) Issue(domain string) (*tls.Certificate, error) {
	if v, ok := l.cache.Get(domain); ok {
		cert := v.(*tls.Certificate)

		if cert.Leaf.NotAfter.After(time.Now().Add(1 * time.Minute)) {
			return cert, nil
		}
	}

	v, err, _ := l.group.Do(domain, func() (interface{}, error) {
		cert, err := l.load(domain)
		if err == nil {
			l.cache.Add(domain, cert)
			log.Printf("loaded certificate for %v (expires %v)", domain, cert.Leaf.NotAfter)
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

func (l *Loader) load(domain string) (*tls.Certificate, error) {
	cp := path.Join(l.Dir, domain, "cert.pem")
	cd, err := load(cp)
	if err != nil {
		return nil, err
	}

	c, err := x509.ParseCertificate(cd.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate from '%v': %v", cp, err)
	}

	kp := path.Join(l.Dir, domain, "key.pem")
	kd, err := load(kp)
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
			return nil, fmt.Errorf("failed to load private key from '%v': %v", kp, err)
		}
	}

	return &tls.Certificate{
		Certificate: [][]byte{cd.Bytes},
		PrivateKey: k,
		Leaf: c,
	}, nil
}
