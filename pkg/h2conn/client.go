package h2conn

import (
    "context"
    "io"
    "net/http"

    "golang.org/x/net/http2"
)

type Client struct {
    Method string
    Header http.Header
    Client *http.Client
}

func (c *Client) Connect(ctx context.Context, urlStr string) (*Conn, *http.Response, error) {
    reader, writer := io.Pipe()

    req, err := http.NewRequest(c.Method, urlStr, reader)
    if err != nil {
	return nil, nil, err
    }

    if c.Header != nil {
	req.Header = c.Header
    }

    req = req.WithContext(ctx)

    httpClient := c.Client
    if httpClient == nil {
	httpClient = defaultClient.Client
    }

    resp, err := httpClient.Do(req)
    if err != nil {
	return nil, nil, err
    }

    conn, ctx := newConn(req.Context(), resp.Body, writer)

    resp.Request = req.WithContext(ctx)

    return conn, resp, nil
}

var defaultClient = Client{
    Method: http.MethodPost,
    Client: &http.Client{Transport: &http2.Transport{}},
}

func Connect(ctx context.Context, urlStr string) (*Conn, *http.Response, error) {
    return defaultClient.Connect(ctx, urlStr)
}

