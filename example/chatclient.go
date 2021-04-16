package main

import (
//	"bufio"
	"context"
	"crypto/tls"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/sha256"
	"encoding/gob"
	"encoding/pem"
	"io/ioutil"
	"fmt"
	"log"
	"net/http"
//	"os"
//	"strings"

	"h2conn"
	"golang.org/x/net/http2"
)

const url = "https://localhost:8000"

func main() {
    ctx := setContext()
    c := setupClient()
    conn, _, err := clientConnect(c, ctx, url)
    defer conn.Close()

    var in, out = gob.NewDecoder(conn), gob.NewEncoder(conn)

    var res []byte
    err = clientHello(conn, in, out, &res)
    if err != nil {
	log.Fatalf("error in client hello: %v", err)
    }
    fmt.Printf("recv: %x\n", res)
    ClientDecryptReturnAuthChallengeBytes(in, out, &res)
    var x string
    err = in.Decode(&x)
    fmt.Printf("response: %s\n", x)
//    fmt.Print("Name: ")
//    nameReader := bufio.NewReader(os.Stdin)
//    name, _ := nameReader.ReadString('\n')
//    name = strings.TrimRight(name, "\n")
//    err = out.Encode(name)
//    if err != nil {
//	log.Fatalf("Failed send login name: %v", err)
//    }

//    var loginResp string
//    err = in.Decode(&loginResp)
//    if err != nil {
//	log.Fatalf("Failed login: %v", err)
//   }
//    if loginResp != "ok" {
//	log.Fatalf("Failed login: %s", loginResp)
//   }
    err = out.Encode("poop")
    checkError(err)
    var cmd string
    for cmd != "quit" {
	err := in.Decode(&cmd)
	if err != nil {
	    fmt.Printf("error receiving command from server\n")
	    return
	}
	fmt.Printf("cmd received: %s\n", cmd)
    }
}

func setContext() context.Context {
    return context.Background()
}

func setupClient() *h2conn.Client {
    c := &h2conn.Client{
	Client: &http.Client{
	    Transport: &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	},
    }
    return c
}

func clientConnect(client *h2conn.Client, ctx context.Context, url string) (*h2conn.Conn, *http.Response, error) {
    conn, resp, err := client.Connect(ctx, url)
    if err != nil {
	log.Fatalf("failed to initiate connection: %s", err)
    }
    if resp.StatusCode != http.StatusOK {
	log.Fatalf("bad status code: %s", resp.StatusCode)
    }
    return conn, resp, err
}

func clientHello(conn *h2conn.Conn, in *gob.Decoder, out *gob.Encoder, res *[]byte) error {
    err := in.Decode(res)
    if err != nil {
	return err
    }
    return nil
}

func ClientReadAuthPrivKey() *rsa.PrivateKey {
    privkeypemdata, err := ioutil.ReadFile("../data/auth/private.rsapem.key")
    checkError(err)
    block, _ := pem.Decode(privkeypemdata)
    if block == nil {
	log.Fatalf("failed to read privkey pem file\n")
    }
    privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
	return nil
    }
    return privkey
}


func ClientDecryptReturnAuthChallengeBytes(in *gob.Decoder, out *gob.Encoder, cipher *[]byte) {
    priv := ClientReadAuthPrivKey()
    var msg []byte
    rng := rand.Reader
    if priv == nil {
	log.Fatalf("failed to read priv key file")
    }
    msg, err := rsa.DecryptOAEP(sha256.New(), rng, priv, *(cipher), nil)
    checkError(err)
    err = out.Encode(msg)
}


func checkError(err error) {
    if err != nil {
	log.Fatalln("fatal error: ", err.Error())
    }
}

//login
/* 
1. server create random bytes R
2. server encrypt R with public rsa key creating E
3. server send E to client
4. client decrypt E with private rsa key creating X
5. client send X to server
6. server verify that X == R
    -> if so, continue execution
    -> if no match, immediately close connection
*/
