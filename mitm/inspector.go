package mitm

import (
	"net/http"
)


// `Inspector` allows proxied requests to be inspected and optionally rejected.
type Inspector interface {
	// Return 0 to allow the request, or an HTTP status code to reject it.
	Inspect(req *http.Request) int
}
