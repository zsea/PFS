package main

import (
	"fmt"
	"net/url"
)

// 1. 声明保存命令行参数的变量
var (
	listen *url.URL
	server *url.URL
)

func main() {
	var listen_arg string
	var server_arg string
	var pub string
	var isHelp bool
	var showVersion bool
	Usages.AppendString(&listen_arg, "l", "listen", "", "监听方式")
	Usages.AppendString(&server_arg, "s", "server", "", "服务端地址")
	Usages.AppendString(&pub, "", "pub", "", "公钥文件地址")
	Usages.AppendBool(&isHelp, "h", "help", false, "查看帮助文档")
	Usages.AppendBool(&showVersion, "v", "version", false, "查看版本信息")

	Usages.Parse()
	LoggerInitialization()

	if isHelp {
		Usages.Usages()
		return
	} else if showVersion {
		fmt.Println(Version)
		return
	}

	var err error
	pki, err := LoadPKIFromFile(pub)
	if err != nil {
		panic(err)
	}
	LocalPKI = *pki
	localUserId = pki.GetMd5()
	logger.Infof("当前账号：%s", localUserId)
	if len(listen_arg) > 0 {
		listen, err = url.Parse(listen_arg)
		if err != nil {
			logger.Errorf("监听地址无效")
			return
		}
		if listen.Scheme != "quic" {
			logger.Errorf("不支持的监听地址")
			return
		}
		if listen.Scheme == "quic" {
			RunTask(func() {
				StartQuicService(listen.Host)
			})

		}
	}
	if len(server_arg) > 0 {
		server, err = url.Parse(server_arg)
		if err != nil {
			logger.Errorf("服务端地址无效")
			return
		}
		if server.Scheme != "quic" {
			logger.Errorf("不支持的服务端地址")
			return
		}
		if server.Scheme == "quic" {

			RunTask(func() {
				StartQuicClient(server.Host)
			})
		}
	}
	wg.Wait()
	// logger.Infof("监听地址:%s", listenUrl.Host)
	// // 调用 LoadPublicKey 函数加载公钥
	// publicKey, err := LoadPKIFromFile(nil)
	// if err != nil {
	// 	fmt.Printf("加载公钥文件失败：%v\n", err)
	// 	return
	// }

	// fmt.Println("公钥内容：")
	// fmt.Println(publicKey)
	// fmt.Println("MD5:")
	// fmt.Println(publicKey.GetMd5())
	// StartQuicService("localhost:4252")
}
