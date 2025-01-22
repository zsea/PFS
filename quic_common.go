package main

import (
	"context"
	"io"
	"time"

	"github.com/quic-go/quic-go"
)

func _Ping(ctx context.Context, stream quic.Stream) {
	for {
		select {
		case <-ctx.Done(): // 检查是否收到取消信号
			return
		case <-time.After(10 * time.Second):
			stream.Write([]byte{1})

		}
	}
}
func _Authentication(stream quic.Stream, conn quic.Connection) (bool, string) {
	// 读取客户端发送的数据
	data := make([]byte, 3)
	n, err := QuicStreamReadWithTimeout(stream, data, 10)
	if err != nil {
		if err == io.EOF {
			logger.Infof("客户端关闭连接：%s", conn.RemoteAddr().String())

		}
		defer conn.CloseWithError(0, "")
		return false, ""
	}
	if n != 3 && string(data) != "PFS" {
		logger.Infof("%s 不是有效的客户端", conn.RemoteAddr().String())
		defer conn.CloseWithError(0, "")
		return false, ""
	}
	data = make([]byte, 1)
	_, err = QuicStreamReadWithTimeout(stream, data, 10)
	if err != nil {
		if err == io.EOF {
			logger.Infof("客户端关闭连接：%s", conn.RemoteAddr().String())

		}
		defer conn.CloseWithError(0, "")
		return false, ""
	}
	if data[0] != 0 {
		//指令0，表示上报的是客户端的公钥信息
		logger.Infof("对端指令不正确：%d", data[0])
		defer conn.CloseWithError(0, "")
		return false, ""
	}
	data = make([]byte, 2)
	_, err = QuicStreamReadWithTimeout(stream, data, 10)
	if err != nil {
		if err == io.EOF {
			logger.Infof("客户端关闭连接：%s", conn.RemoteAddr().String())

		}
		defer conn.CloseWithError(0, "")
		return false, ""
	}
	oLen := BytesToUint(data)
	data = make([]byte, oLen)
	_, err = QuicStreamReadWithTimeout(stream, data, 10)
	if err != nil {
		if err == io.EOF {
			logger.Infof("客户端关闭连接：%s", conn.RemoteAddr().String())

		}
		defer conn.CloseWithError(0, "")
		return false, ""
	}
	pub := string(data)
	pki, err := LoadPKIFromContent(pub)
	if err != nil {
		logger.Infof("公钥信息解析失败：%s", pub)
		defer conn.CloseWithError(0, "")
		return false, ""
	}
	uid := pki.GetMd5()
	conn_info := ConnectionInfo{
		UID:     uid,
		Conn:    conn,
		PKI:     *pki,
		Command: stream,
	}
	err = Clients.Store(uid, conn_info)
	if err != nil {
		logger.Infof("已连接到账号:%s", uid)
		return false, uid
	}
	logger.Infof("uid:%s", uid)
	logger.Infof("pub:%s", pki.Origin)
	logger.Infof("当前连接数：%d", Clients.Count())
	return true, uid
}
func _SendAuthentication(stream quic.Stream) {
	//ctx, cancel := context.WithCancel(context.Background()) // 创建一个可取消的context
	//defer cancel()
	_, err := stream.Write([]byte("PFS"))
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
}
func QuicMainStream(stream quic.Stream, conn quic.Connection, isServer bool) {
	ctx, cancel := context.WithCancel(context.Background()) // 创建一个可取消的context
	defer cancel()
	defer stream.Close()

	var uid string
	if isServer {
		success, _uid := _Authentication(stream, conn)
		if !success {
			return
		}
		uid = _uid
		_SendAuthentication(stream)
	} else {
		_SendAuthentication(stream)
		success, _uid := _Authentication(stream, conn)
		if !success {
			return
		}
		uid = _uid
		//客户端，执行Ping
		go _Ping(ctx, stream)
	}
	commands := make([]byte, 1)

	defer func() {
		logger.Infof("%s 已断开", conn.RemoteAddr().String())
		Clients.Pool.Delete(uid)
		logger.Infof("当前连接数：%d", Clients.Count())
	}()
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
