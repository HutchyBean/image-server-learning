package main

import "os"

var signToken string

func main() {
	signToken = os.Getenv("supersecretsigning")
	InitDB()
	InitServer()
}
