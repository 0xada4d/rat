package h2conn

import (
    "fmt"
    "io"
    "net/http"
)

var ErrHTTP2NotSupported = fmt.Errorf("HTTP2 not supported")

type Server struct {
    StatusCode int
}

func (u *Server) Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
    if !r.ProtoAtLeast(2, 0) {
	return nil, ErrHTTP2NotSupported
    }

    flusher, ok := w.(http.Flusher)
    if !ok {
	return nil, ErrHTTP2NotSupported
    }

    c, ctx := newConn(r.Context(), r.Body, &flushWrite{w: w, f: flusher})

    *r = *r.WithContext(ctx)

    w.WriteHeader(u.StatusCode)
    flusher.Flush()

    return c, nil
}

var defaultUpgrader = Server{
    StatusCode: http.StatusOK,
}

func Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
    return defaultUpgrader.Accept(w, r)
}

type flushWrite struct {
    w io.Writer
    f http.Flusher
}

func (w *flushWrite) Write(data []byte) (int, error) {
    n, err := w.w.Write(data)
    w.f.Flush()
    return n, err
}

func (w *flushWrite) Close() error {
    return nil
}
