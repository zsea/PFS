package main

import "encoding/binary"

func ClearBytes(bytes []byte, len int) {
	for i := range len {
		bytes[i] = 0
	}
}
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
