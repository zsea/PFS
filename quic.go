package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"

	quic "github.com/quic-go/quic-go"
)

func StartQuicService(addr string) error {

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

		go _handleConnection(conn)
	}
}

// handleConnection 处理每个QUIC连接
func _handleConnection(s quic.Connection) {
	logger.Infof("新连接: %s", s.RemoteAddr().String())

	// 处理每个流
	for {
		stream, err := s.AcceptStream(context.Background())
		if err != nil {
			logger.Infof("接受流失败: %v", err)
			return
		}
		go _handleStream(stream)
	}
}

// handleStream 处理每个QUIC流
func _handleStream(stream quic.Stream) {
	defer stream.Close()

	// 读取客户端发送的数据
	data := make([]byte, 1024)
	for {
		n, err := stream.Read(data)
		if err != nil {
			if err == io.EOF {
				//fmt.Printf("客户端关闭连接: %s\n", stream.StreamID().s)
				return
			}
			logger.Infof("读取数据失败: %v", err)
			return
		}

		// 将数据原样返回给客户端
		if _, err := stream.Write(data[:n]); err != nil {
			logger.Infof("写入数据失败: %v", err)
			return
		}
	}
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
		NextProtos:   []string{"quic-echo-example"},
	}
}
