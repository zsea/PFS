package main

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/quic-go/quic-go"
)

func BytesToUint(data []byte) uint {
	if len(data) < 2 {
		panic("data length can not low 2")
	}

	// 假设使用大端字节序（Big-Endian）
	// data[0] 是高字节，data[1] 是低字节
	return uint(data[0])<<8 | uint(data[1])
}
func Uint16ToBigEndian(value uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, value)
	return data
}

func (s *ConnectionPools) Count() int {
	count := 0

	s.Pool.Range(func(key, value interface{}) bool {
		count++
		return true // 继续遍历
	})
	return count
}
func (p *ConnectionPools) Store(uid string, conn ConnectionInfo) error {
	_, exists := p.Pool.Load(uid)
	if exists {
		return errors.New("uid connected")
	}
	p.Pool.Store(uid, conn)
	return nil
}
func QuicStreamReadWithTimeout(stream quic.Stream, p []byte, timeout int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	done := make(chan bool)
	var n int
	var err error
	go func() {
		n, err = stream.Read(p)

		done <- true
	}()
	select {
	case <-done:
		return n, err
	case <-ctx.Done():
		return 0, errors.New("read operation timed out")
	}
}
func RunSafely(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic:", r)
		}
	}()
	fn()
}
