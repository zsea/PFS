package main

import (
	"context"
	"crypto/tls"
	"io"
	"time"

	quic "github.com/quic-go/quic-go"
)

func _StartMainStream(conn quic.Connection) {
	defer wg.Done()
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}
	defer stream.Close()
	for {
		message := "test"
		logger.Debugf("Client: Sending '%s'", message)
		_, err = stream.Write([]byte(message))
		if err != nil {
			panic(err)
		}

		buf := make([]byte, len(message))
		_, err = io.ReadFull(stream, buf)
		if err != nil {
			panic(err)
		}
		logger.Debugf("Client: Got '%s'", buf)
		time.Sleep(5*time.Second)
	}
}
func StartQuicClient(addr string) {
	defer wg.Done()
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"PFS"},
	}
	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, nil)
	if err != nil {
		panic(err)
		
	}
	RunTask(func() { _StartMainStream(conn) })
	
}
