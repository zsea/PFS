package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	quic "github.com/quic-go/quic-go"
)

func StartQuicService(addr string) error {

	defer wg.Done()
	listener, err := quic.ListenAddr(addr, _generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	defer listener.Close()
	logger.Infof("QUIC服务端启动，监听地址: %s", addr)

	// 接受连接
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logger.Infof("接受连接失败 %v", err)
			continue
		}
		RunTask(func() { _handleConnection(conn) })
		//go _handleConnection(conn)
	}
}

// handleConnection 处理每个QUIC连接
func _handleConnection(conn quic.Connection) {
	defer wg.Done()
	logger.Infof("新连接: %s", conn.RemoteAddr().String())
	defer func() {
		conn.CloseWithError(0, "")
	}()
	// 处理每个流
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			logger.Infof("接受流失败: %v", err)
			//panic(err)
			//return
			return
		}
		RunTask(func() { _handleStream(stream, conn) })

	}
}

// handleStream 处理每个QUIC流
func _handleStream(stream quic.Stream, conn quic.Connection) {
	wg.Done()
	QuicMainStream(stream, conn, true)
}

// Setup a bare-bones TLS config for the server
func _generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"PFS"},
	}
}
