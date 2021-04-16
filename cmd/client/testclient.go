package main

import (
    "10.9.9.2/rat/pkg/client"
)

func main() {
    cl := client.Instantiate("localhost", "8000", "h2", "../../data/auth/private.rsapem.key")
    cl.Run()
}
