package main

import (
	_ "embed"
	"sync"
)

type ConnectionPools struct {
	Pool sync.Map
}
type ConnectionType byte

const (
	CT_PKI   ConnectionType = iota // 0，通过PKI信息进行身份认证
	CT_TOKEN                       // 1，通过Token进行身份认证
)

var wg sync.WaitGroup
var localUserId string
var LocalPKI PublicKeyInfo

//go:embed version
var Version string

type Task func()

func RunTask(task Task) {
	wg.Add(1)
	go task()
}
