package main

import (
    "crypto/rsa"
    "crypto/rand"
    "os"
    "fmt"
    "crypto/x509"
    "encoding/pem"
)


func main() {
    reader := rand.Reader
    bitSize := 4096
    privkey, err := rsa.GenerateKey(reader, bitSize)
    checkError(err)
    pubkey := privkey.PublicKey

    savePEMKey("private.rsapem.key", privkey)
    savePublicPEMKey("public.rsapem.key", pubkey)

}

func savePEMKey(filename string, key *rsa.PrivateKey) {
    outfile, err := os.Create(filename)
    checkError(err)
    defer outfile.Close()

    var privateKey = &pem.Block{
	Type: "PRIVATE KEY",
	Bytes: x509.MarshalPKCS1PrivateKey(key),
    }

    err = pem.Encode(outfile, privateKey)
    checkError(err)
}

func savePublicPEMKey(filename string, pubkey rsa.PublicKey) {
    asn1bytes, err := x509.MarshalPKIXPublicKey(&pubkey)
    checkError(err)

    var pemkey = &pem.Block{
	Type: "PUBLIC KEY",
	Bytes: asn1bytes,
    }

    pemfile, err := os.Create(filename)
    checkError(err)
    defer pemfile.Close()

    err = pem.Encode(pemfile, pemkey)
    checkError(err)
}

func checkError (err error) {
    if err != nil {
	fmt.Println("fatal error: ", err.Error())
	os.Exit(1)
    }
}
