package main

import (
	"time"

	quic "github.com/quic-go/quic-go"
)

type ConnectionInfo struct {
	UID      string
	Conn     quic.Connection
	Command  quic.Stream
	PKI      PublicKeyInfo
	OnlineAt time.Time // 上线时间
}
