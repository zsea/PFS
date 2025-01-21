package main

import (
	_ "embed"
	"sync"
)

var wg sync.WaitGroup
var Clients sync.Map
var localUserId string
var LocalPKI PublicKeyInfo

//go:embed version
var Version string

type Task func()

func RunTask(task Task) {
	wg.Add(1)
	go task()
}
