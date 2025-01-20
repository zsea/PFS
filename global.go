package main

import (
	_ "embed"
	"sync"
)

var wg sync.WaitGroup

//go:embed version
var Version string

type Task func()

func RunTask(task Task) {
	wg.Add(1)
	go task()
}
