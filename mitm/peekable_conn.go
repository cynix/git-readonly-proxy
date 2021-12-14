package mitm

import (
	"bufio"
	"net"
)


// `PeekableConn` allows peeking at a connection's data.
type PeekableConn struct {
	net.Conn

	r *bufio.Reader

	addr httpAddr
	host string
}

type httpAddr string

// `NewPeekableConn` wraps a `net.Conn` to make it peekable.
func NewPeekableConn(c net.Conn, addr, host string) *PeekableConn {
	return &PeekableConn{
		Conn: c,
		r: bufio.NewReader(c),
		addr: httpAddr(addr),
		host: host,
	}
}

// `Host` returns the connection's destination.
func (c *PeekableConn) Host() string {
	return c.host
}

// `Peek` returns the next `n` bytes without advancing the reader.
func (c *PeekableConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

// `Read` reads data into `b` and advances the reader.
func (c *PeekableConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// `RemoteAddr` returns the connection's originator.
func (c *PeekableConn) RemoteAddr() net.Addr {
	return c.addr
}

func (a httpAddr) Network() string {
	return "http"
}

func (a httpAddr) String() string {
	return string(a)
}
