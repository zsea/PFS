package main

import (
	"crypto/md5"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
)

type UserStream struct {
	Stream quic.Stream
	Conn   quic.Connection
}
type UserConnection struct { //暂未使用
	Conn    quic.Connection
	Streams []UserStream
}
type User struct {
	UID    string
	PKI    PublicKeyInfo
	Stream []UserStream
}
type Users struct {
	Users sync.Map
}

func (u *Users) StoreWithUid(uid string, pki PublicKeyInfo, stream UserStream) error {

	e, ok := u.Users.Load(uid)
	if !ok {
		u.Users.Store(uid, User{UID: uid, PKI: pki, Stream: []UserStream{stream}})
	} else { //存在，则直接加入
		uu := e.(User)
		uu.Stream = append(uu.Stream, stream)
	}
	return nil
}
func (u *Users) StoreWithToken(token string, stream UserStream) (string, error) {
	t, err := Tokens.LoadAndDelete(token)
	if err != nil {
		return "", err
	}
	err = u.StoreWithUid(t.pki.GetMd5(), t.pki, stream)
	if err != nil {
		return "", err
	}
	return t.pki.GetMd5(), nil
}
func (u *Users) Count() int {
	count := 0

	u.Users.Range(func(key, value interface{}) bool {
		count++
		return true // 继续遍历
	})
	return count
}
func (u *Users) Remove(uid string, conn quic.Connection) {
	e, ok := u.Users.Load(uid)
	if !ok {
		return
	}
	uu := e.(User)
	ss := []UserStream{}
	for _, s := range uu.Stream {
		if s.Conn.RemoteAddr().String() != conn.RemoteAddr().String() {
			ss = append(ss, s)
		}
	}
	uu.Stream = ss
}

type Token struct {
	token    string
	pki      PublicKeyInfo
	cratedAt uint
}
type TokenStore sync.Map

func (t *TokenStore) Add(token string, pki PublicKeyInfo) error {
	m := (*sync.Map)(t)
	if _, ok := m.Load(token); ok {
		return errors.New("key is exists")
	}
	m.Store(token, Token{token: token, pki: pki, cratedAt: 0})
	return nil
}
func (t *TokenStore) LoadAndDelete(token string) (*Token, error) {
	m := (*sync.Map)(t)
	if v, ok := m.LoadAndDelete(token); ok {
		return v.(*Token), nil
	}
	return nil, errors.New("not found")
}

var Clients Users //
var Servers Users //
var Tokens TokenStore

// PublicKeyInfo 用于存储公钥文件的指数和模数
type PublicKeyInfo struct {
	Exponent int
	Modulus  []byte
	Origin   string
}

// GetMd5 计算 Exponent 和 Modulus 合并后的 MD5 值
func (pki *PublicKeyInfo) GetMd5() string {
	// 将 Exponent 转换为 byte 数组
	exponentBytes := big.NewInt(int64(pki.Exponent)).Bytes()

	// 合并 Exponent 和 Modulus
	combined := append(exponentBytes, pki.Modulus...)

	// 计算 MD5 值
	hash := md5.Sum(combined)
	return hex.EncodeToString(hash[:])
}
func LoadPKIFromContent(content string) (*PublicKeyInfo, error) {
	// 解析 OpenSSH 格式的公钥
	publicKeyInfo, err := _parseOpenSSHPublicKey(content)
	if err != nil {
		return nil, err
	}

	return publicKeyInfo, nil
}

// LoadPublicKeyInfo 用于从 id_rsa.pub 文件中加载公钥信息
func LoadPKIFromFile(path string) (*PublicKeyInfo, error) {
	filePath := path
	// 如果 path 为 nil，则从用户目录读取
	if len(filePath) == 0 {
		// 获取当前用户主目录
		currentUser, err := user.Current()
		if err != nil {
			return nil, err
		}
		filePath = currentUser.HomeDir + "/.ssh/id_rsa.pub"
	}
	logger.Info("公钥地址：" + filePath)
	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// 解析 OpenSSH 格式的公钥
	publicKeyInfo, err := _parseOpenSSHPublicKey(string(data))
	if err != nil {
		return nil, err
	}

	return publicKeyInfo, nil
}

// parseOpenSSHPublicKey 解析 OpenSSH 格式的公钥
func _parseOpenSSHPublicKey(key string) (*PublicKeyInfo, error) {
	// 去除首尾空白字符
	key = strings.TrimSpace(key)

	// 分割字符串，获取 Base64 编码的公钥部分
	parts := strings.Fields(key)
	if len(parts) < 2 || parts[0] != "ssh-rsa" {
		return nil, fmt.Errorf("无效的公钥格式")
	}
	base64Key := parts[1]

	// 解码 Base64 编码的公钥
	decodedKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, err
	}

	// 解析公钥
	var rsaPubKey rsa.PublicKey
	err = _sshParsePublicKey(decodedKey, &rsaPubKey)
	if err != nil {
		return nil, err
	}

	// 创建 PublicKeyInfo 实例并填充数据
	publicKeyInfo := &PublicKeyInfo{
		Exponent: rsaPubKey.E,
		Modulus:  rsaPubKey.N.Bytes(),
		Origin:   key,
	}

	return publicKeyInfo, nil
}

// sshParsePublicKey 解析 OpenSSH 格式的公钥数据
func _sshParsePublicKey(data []byte, rsaPubKey *rsa.PublicKey) error {
	// 解析公钥数据
	var (
		n   int
		err error
	)

	// 读取字符串 "ssh-rsa"
	_, n, err = _readString(data, 0)
	if err != nil {
		return err
	}

	// 读取指数
	eBytes, n, err := _readBigInt(data, n)
	if err != nil {
		return err
	}
	rsaPubKey.E = int(eBytes.Int64())

	// 读取模数
	nBytes, n, err := _readBigInt(data, n)
	if err != nil {
		return err
	}
	rsaPubKey.N = nBytes

	return nil
}

// readString 读取一个字符串
func _readString(data []byte, offset int) (string, int, error) {
	length := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4
	if offset+length > len(data) {
		return "", 0, fmt.Errorf("读取字符串失败")
	}
	str := string(data[offset : offset+length])
	offset += length
	return str, offset, nil
}

// readBigInt 读取一个大整数
func _readBigInt(data []byte, offset int) (*big.Int, int, error) {
	length := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4
	if offset+length > len(data) {
		return nil, 0, fmt.Errorf("读取大整数失败")
	}
	bigInt := big.NewInt(0).SetBytes(data[offset : offset+length])
	offset += length
	return bigInt, offset, nil
}
