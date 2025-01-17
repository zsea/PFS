package main

import "sync"

var wg sync.WaitGroup

type Task func()

func RunTask(task Task) {
	wg.Add(1)
	go task()
}
