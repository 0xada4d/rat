package main

import (
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"sync"
	"os"
	"bufio"
	"strings"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/sha256"
	"io/ioutil"
	"encoding/pem"

	"h2conn"
)

type encoder interface {
	Encode(interface{}) error
}

type server struct {
	conns map[string]encoder
	lock  sync.RWMutex
}

func main() {
	c := server{conns: make(map[string]encoder)}
	srv := &http.Server{Addr: ":8000", Handler: &c}
	log.Printf("Serving on http://0.0.0.0:8000")
	log.Fatal(srv.ListenAndServeTLS("../data/x509/server.crt", "../data/x509/server.key"))
}

func (c *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := h2conn.Accept(w, r)
	if err != nil {
		log.Printf("Failed creating http2 connection: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	var (
		in, out = gob.NewDecoder(conn), gob.NewEncoder(conn)
		log = logger{remoteAddr: r.RemoteAddr}
	)
    err = ServerAuthChallenge(in, out)
    checkError(err)

	var name string
	err = in.Decode(&name)
	if err != nil {
		log.Printf("Failed reading login name: %v", err)
		return
	}

	log.Printf("Got login: %s", name)

	err = c.login(name, out)
	if err != nil {
		err = out.Encode(err.Error())
		if err != nil {
			log.Printf("Failed sending login response: %v", err)
		}
		return
	}
	err = out.Encode("ok")
	if err != nil {
		log.Printf("Failed sending login response: %v", err)
		return
	}

	defer c.logout(name)

	defer log.Printf("User logout: %s", name)

	prompt(r, in, out)
}

func (c *server) login(name string, enc encoder) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if _, ok := c.conns[name]; ok {
		return fmt.Errorf("user already exists")
	}
	c.conns[name] = enc
	return nil
}

func (c *server) logout(name string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.conns, name)
}

type logger struct {
	remoteAddr string
}

func (l logger) Printf(format string, args ...interface{}) {
	log.Printf("[%s] %s", l.remoteAddr, fmt.Sprintf(format, args...))
}

func ServerReadAuthPubKey() *rsa.PublicKey {
    pubkeypemdata, err := ioutil.ReadFile("../data/auth/public.rsapem.key")
    checkError(err)
    block, _ := pem.Decode(pubkeypemdata)
    if block == nil {
	log.Fatalf("failed to read pubkey pem file")
    }
    pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
    checkError(err)
    switch pubkey := pubkey.(type) {
    case *rsa.PublicKey:
	return pubkey
    default:
	break
    }
    return nil
}

func ServerEncryptAuthChallengeBytes(pub *rsa.PublicKey, text []byte) ([]byte) {
    rng := rand.Reader
    encText, err := rsa.EncryptOAEP(sha256.New(), rng, pub, text, nil)
    checkError(err)
    return encText
}

func ServerAuthChallenge(in *gob.Decoder, out *gob.Encoder) error {
    x := 64
    r := make([]byte, x)
    _, err := rand.Read(r)
    if err != nil {
	return err
    }
    rsaPubKey := ServerReadAuthPubKey()
    fmt.Printf("orig: %x\n", r)
    var rEnc []byte
    if rsaPubKey != nil {
	rEnc = ServerEncryptAuthChallengeBytes(rsaPubKey, r)
    }
    if rEnc == nil {
	log.Fatalf("failed to encrypt challenge bytes\n")
    }
    fmt.Println("sending auth challenge")
    err = out.Encode(rEnc)
    checkError(err)
    var msg []byte
    err = in.Decode(&msg)
    checkError(err)
    fmt.Println("recieved auth challenge response")
    if bytes.Equal(r, msg) {
	fmt.Println("client passed auth challenge")
    } else {
	log.Fatalf("client did not pass auth challenge")
    }

    return nil
}



func prompt(r *http.Request, in *gob.Decoder, out *gob.Encoder) {
    fmt.Printf("Using: %s\n", r.Proto)
    for r.Context().Err() == nil {
	fmt.Printf("CMD > ")
	cmdReader := bufio.NewReader(os.Stdin)
	cmd, _ := cmdReader.ReadString('\n')
	cmd = strings.TrimRight(cmd, "\n")
	if (cmd == "") {
	    continue
	}
	err := out.Encode(cmd)
	if err != nil {
	    fmt.Printf("error sending command\n")
	}
	cmd = ""
    }
}
	
func checkError(err error) {
    if err != nil {
	log.Fatalln("fatal error: ", err.Error())
    }
}


