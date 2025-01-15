package main

import (
	"fmt"
)

// LoadPublicKey 用于加载 id_rsa.pub 文件

func main() {
	// 调用 LoadPublicKey 函数加载公钥
	publicKey, err := LoadUser(nil)
	if err != nil {
		fmt.Printf("加载公钥文件失败：%v\n", err)
		return
	}

	fmt.Println("公钥内容：")
	fmt.Println(publicKey)
	fmt.Println("MD5:")
	fmt.Println(publicKey.GetMd5())
}
