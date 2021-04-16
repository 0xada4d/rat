package c2err

import (
    "log"
)

func CheckError(err error) {
    if err != nil {
	log.Fatalf("fatal error: ", err.Error())
    }
}
