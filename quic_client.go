package main

import (
	"context"
	"crypto/tls"
	"io"

	quic "github.com/quic-go/quic-go"
)

func StartQuicClient(addr string) error {
	defer wg.Done()
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, nil)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()
	message := "test"
	logger.Debugf("Client: Sending '%s'", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	logger.Debugf("Client: Got '%s'", buf)
	select {}
	return nil
}
