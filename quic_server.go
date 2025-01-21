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

	// 处理每个流
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			logger.Infof("接受流失败: %v", err)
			panic(err)
			//return
		}
		RunTask(func() { _handleStream(stream, conn) })

	}
}

// handleStream 处理每个QUIC流
func _handleStream(stream quic.Stream, conn quic.Connection) {
	defer wg.Done()
	defer stream.Close()

	// 读取客户端发送的数据
	data := make([]byte, 3)
	n, err := stream.Read(data)
	if err != nil {
		if err == io.EOF {
			logger.Infof("客户端关闭连接：%s", conn.RemoteAddr().String())
			defer conn.CloseWithError(0, "")
			return
		}
		panic(err)
	}
	if n != 3 && string(data) != "PFS" {
		logger.Infof("%s 不是有效的客户端", conn.RemoteAddr().String())
		defer conn.CloseWithError(0, "")
		return
	}
	data = make([]byte, 1)
	_, err = stream.Read(data)
	if err != nil {
		if err == io.EOF {
			logger.Infof("客户端关闭连接：%s", conn.RemoteAddr().String())
			defer conn.CloseWithError(0, "")
			return
		}
		panic(err)
	}
	if data[0] != 0 {
		//指令0，表示上报的是客户端的公钥信息
		logger.Infof("客户端指令不正确：%d", data[0])
		defer conn.CloseWithError(0, "")
		return
	}
	data = make([]byte, 2)
	_, err = stream.Read(data)
	if err != nil {
		if err == io.EOF {
			logger.Infof("客户端关闭连接：%s", conn.RemoteAddr().String())
			defer conn.CloseWithError(0, "")
			return
		}
		panic(err)
	}
	oLen := BytesToUint(data)
	data = make([]byte, oLen)
	_, err = stream.Read(data)
	if err != nil {
		if err == io.EOF {
			logger.Infof("客户端关闭连接：%s", conn.RemoteAddr().String())
			defer conn.CloseWithError(0, "")
			return
		}
		panic(err)
	}
	pub := string(data)
	pki, err := LoadPKIFromContent(pub)
	if err != nil {
		logger.Infof("公钥信息解析失败：%s", pub)
		defer conn.CloseWithError(0, "")
		return
	}
	uid := pki.GetMd5()
	conn_info := ConnectionInfo{
		UID:     uid,
		Conn:    conn,
		Command: stream,
	}
	Clients.Store(uid, conn_info)
	logger.Infof("uid:%s", uid)
	logger.Infof("pub:%s", pki.Origin)
	commands := make([]byte, 1)
	for {
		_, err := stream.Read(commands)
		if err != nil {

			logger.Infof("读取指令失败: %v", err)
			defer conn.CloseWithError(0, "")
			return
		}

		command := commands[0]
		if command == 1 {
			// 指令1：ping消息，需要回复pong消息（指令2）
			logger.Infof("%s 指令 ping", conn.RemoteAddr().String())
			if _, err := stream.Write([]byte{2}); err != nil {
				logger.Infof("写入数据失败: %v", err)
				return
			}
		} else if command == 2 {
			logger.Infof("%s 指令 pong", conn.RemoteAddr().String())
		} else if command == 3 || command == 4 {
			//指令3，回显请求，将会将收到的数据原样以指令4发送回客户端
			len := make([]byte, 2)
			stream.Read(len)
			dataLength := BytesToUint(len)
			playload := make([]byte, dataLength)
			if _, err := stream.Read(playload); err != nil {
				logger.Infof("% 读取echo数据失败: %v", conn.RemoteAddr().String(), err)
				defer conn.CloseWithError(0, "")
				return
			}
			logger.Infof("%s 指令 echo:%s", string(playload))
			if command == 3 {
				msg := append([]byte{0x4}, len...)
				msg = append(msg, playload...)
				if _, err := stream.Read(msg); err != nil {
					logger.Infof("% 写入echo数据失败: %v", conn.RemoteAddr().String(), err)
					defer conn.CloseWithError(0, "")
					return
				}
			}
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
		NextProtos:   []string{"PFS"},
	}
}
