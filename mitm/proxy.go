package mitm

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/cynix/git-readonly-proxy/certs"
)


type Proxy struct {
	Inspector Inspector

	server *http.Server
	client *http.Client
	tlsListener *ConnListener
	tlsServer *http.Server
}

func NewProxy(addr string, issuer certs.Issuer, inspector Inspector) *Proxy {
	proxy := &Proxy{Inspector: inspector}

	proxy.server = &http.Server{
		Addr: addr,
		Handler: proxy,
	}

	proxy.client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			MaxIdleConns: 1024,
			IdleConnTimeout: 60 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
			ForceAttemptHTTP2: false,
		},
		// Let the client handle redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	proxy.tlsListener = &ConnListener{make(chan net.Conn)}
	proxy.tlsServer = &http.Server{
		Handler: tlsHandler{proxy},
		TLSConfig: &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return issuer.Issue(hello.ServerName)
			},
		},
		// Forbid HTTP/2
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	return proxy
}

func (proxy *Proxy) Start() error {
	errs := make(chan error)

	go func() {
		err := proxy.server.ListenAndServe()
		errs <- err
	}()

	go func() {
		err := proxy.tlsServer.ServeTLS(proxy.tlsListener, "", "")
		errs <- err
	}()

	err := <-errs
	return err
}

// Implements `http.Handler`.
func (proxy *Proxy) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.Method == "CONNECT" {
		proxy.connect(res, req)
		return
	}

	if req.URL.Host == "" || !req.URL.IsAbs() {
		// Only absolute requests can be proxied
		res.WriteHeader(http.StatusBadRequest)
		return
	}

	if proxy.Inspector != nil {
		if status := proxy.Inspector.Inspect(req); status != 0 {
			res.WriteHeader(status)
			return
		}
	}

	preq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		res.WriteHeader(http.StatusBadGateway)
		return
	}

	preq.Header = req.Header.Clone()

	pres, err := proxy.client.Do(preq)
	if err != nil {
		res.WriteHeader(http.StatusBadGateway)
		return
	}
	defer pres.Body.Close()

	if pres.Header != nil {
		for k, vv := range pres.Header {
			for _, v := range vv {
				res.Header().Add(k, v)
			}
		}
	}

	res.WriteHeader(pres.StatusCode)

	if pres.Body != nil {
		io.Copy(res, pres.Body)
	}
}

func (proxy *Proxy) connect(res http.ResponseWriter, req *http.Request) {
	c, s := newPipe(req)
	go proxy.unwrap(s)
	defer c.Close()

	conn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		res.WriteHeader(http.StatusBadGateway)
		return
	}
	defer conn.Close()

	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	communicate(c, conn)
}

func (proxy *Proxy) unwrap(p *PeekableConn) {
	b, err := p.Peek(3)
	if err != nil {
		p.Close()
		return
	}

	if b[0] == 0x16 && b[1] == 0x03 && (b[2] >= 0 && b[2] <= 3) {
		// TLS connection
		proxy.tlsListener.Push(p)
	} else {
		// Plaintext connection
		c, err := net.Dial("tcp", p.Host())
		if err != nil {
			p.Close()
			return
		}

		defer c.Close()
		communicate(p, c)
	}
}


func newPipe(req *http.Request) (net.Conn, *PeekableConn) {
	c, s := net.Pipe()
	p := NewPeekableConn(s, req.RemoteAddr, req.Host)
	return c, p
}

func communicate(a, b io.ReadWriteCloser) {
	done := make(chan struct{})
	defer close(done)

	forward := func(dst io.WriteCloser, src io.Reader, errs chan<- error) {
		_, err := io.Copy(dst, src)

		if err == nil {
			if tcp, ok := dst.(*net.TCPConn); ok {
				err = tcp.CloseWrite()
			} else {
				err = dst.Close()
			}
		}

		select {
		case <-done:
			return
		case errs <- err:
			return
		}
	}

	errs := make(chan error)
	go forward(a, b, errs)
	go forward(b, a, errs)

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			return
		}
	}
}


type tlsHandler struct {
	Handler http.Handler
}

func (h tlsHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	h.Handler.ServeHTTP(res, req)
}
