package certs

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"path"
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
	cf := path.Join(l.Dir, domain, "cert.pem")
	kf := path.Join(l.Dir, domain, "key.pem")

	cert, err := tls.LoadX509KeyPair(cf, kf)
	if err != nil {
		return nil, err
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
