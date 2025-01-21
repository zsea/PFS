package main

import (
	"context"
	"crypto/tls"
	"time"

	quic "github.com/quic-go/quic-go"
)

func _Ping(stream quic.Stream) {
	for {
		time.Sleep(10 * time.Second)
		_, err := stream.Write([]byte{1})
		if err!=nil{
			panic(err)
		}
	}
}
func _StartMainStream(conn quic.Connection) {
	defer wg.Done()
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}
	defer stream.Close()
	_, err = stream.Write([]byte("PFS"))
	if err != nil {
		panic(err)
	}
	_, err = stream.Write([]byte{0}) //发送指令0
	if err != nil {
		panic(err)
	}
	oLen := len(LocalPKI.Origin)
	_, err = stream.Write(Uint16ToBigEndian(uint16(oLen)))
	if err != nil {
		panic(err)
	}
	message := []byte(LocalPKI.Origin)

	_, err = stream.Write([]byte(message))
	if err != nil {
		panic(err)
	}
	go _Ping(stream)
	commands := make([]byte, 1)
	for {
		_, err := stream.Read(commands)
		if err != nil {

			logger.Infof("读取指令失败: %v", err)
			panic(err)
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
