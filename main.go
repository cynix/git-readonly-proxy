package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/cynix/git-readonly-proxy/certs"
	"github.com/cynix/git-readonly-proxy/mitm"
)


func main() {
	listen := flag.String("listen", ":8080", "Listening host and port")
	dir := flag.String("certs-dir", "", "Directory containing pre-issued certificates (${certs-dir}/domain.name/cert.pem and ${certs-dir}/domain.name/key.pem)")
	crt := flag.String("ca-cert", "cert.pem", "CA certificate")
	key := flag.String("ca-key", "key.pem", "CA private key")
	flag.Parse()

	var issuer certs.Issuer
	var err error

	if *dir != "" {
		issuer, err = certs.NewLoader(*dir)
	} else {
		issuer, err = certs.NewCA(*crt, *key)
	}

	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("listening on %v", *listen)

	proxy := mitm.NewProxy(*listen, issuer, forbidReceivePack{})
	proxy.Start()
}


type forbidReceivePack struct{}

func (f forbidReceivePack) Inspect(req *http.Request) int {
	if strings.HasSuffix(req.URL.Path, "/git-receive-pack") {
		log.Printf("denying request from %v: %v %v", req.RemoteAddr, req.Method, req.URL)
		return http.StatusForbidden
	}

	log.Printf("allowing request from %v: %v %v", req.RemoteAddr, req.Method, req.URL)
	return 0
}
