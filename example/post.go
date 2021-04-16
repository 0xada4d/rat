package main

import "time"

type Post struct {
    User    string
    Message string
    Time    time.Time
}
