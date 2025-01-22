package main

import (
	"context"
	"crypto/tls"
	"time"

	quic "github.com/quic-go/quic-go"
)

func _StartMainStream(conn quic.Connection) {

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}
	QuicMainStream(stream, conn, false)
}
func StartQuicClient(addr string) {
	defer wg.Done()
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"PFS"},
	}
	for first := true; ; first = false {
		if !first {
			time.Sleep(10 * time.Second)
		}
		conn, err := quic.DialAddr(context.Background(), addr, tlsConf, nil)
		if err != nil {
			logger.Info("连接断开，10秒后重试")
			continue
		}
		//RunTask(func() { _StartMainStream(conn) })
		
		RunSafely(func() {_StartMainStream(conn)})
		conn.CloseWithError(0, "")
		logger.Info("连接断开，10秒后重试")
	}
}
