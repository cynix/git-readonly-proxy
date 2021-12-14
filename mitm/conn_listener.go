package mitm

import (
	"net"
)


// `ConnListener` presents existing connections to the listener.
type ConnListener struct {
	ch chan net.Conn
}

// `Push` makes a connection appear on the `net.Listener` interface.
func (l *ConnListener) Push(c net.Conn) {
	l.ch <- c
}

// Implements `net.Listener`.
func (l *ConnListener) Accept() (net.Conn, error) {
	return <-l.ch, nil
}

// Implements `net.Listener`.
func (l *ConnListener) Close() error {
	return nil
}

// Implements `net.Listener`.
func (l *ConnListener) Addr() net.Addr {
	return nil
}
