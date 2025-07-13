package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// --- 配置项 ---
// 这些变量现在是 var 而不是 const，以便可以从环境变量中覆盖
var (
	listenAddr                 string
	upstreamAddr               string
	upstreamUseTLS             bool
	upstreamInsecureSkipVerify bool
	certFile                   string
	keyFile                    string
)

func init() {
	listenAddr = getEnv("PROXY_LISTEN_ADDR", "0.0.0.0:2525")
	upstreamAddr = getEnv("PROXY_UPSTREAM_ADDR", "mail.cuhk.edu.cn:587")
	upstreamUseTLS = getEnvBool("PROXY_UPSTREAM_USE_TLS", false)
	upstreamInsecureSkipVerify = getEnvBool("PROXY_UPSTREAM_INSECURE_SKIP_VERIFY", true)
	certFile = getEnv("PROXY_CERT_FILE", "cert.pem")
	keyFile = getEnv("PROXY_KEY_FILE", "key.pem")

	log.Println("--- 配置加载 ---")
	log.Printf("监听地址 (PROXY_LISTEN_ADDR): %s", listenAddr)
	log.Printf("上游服务器 (PROXY_UPSTREAM_ADDR): %s", upstreamAddr)
	log.Printf("立即使用TLS连接上游 (PROXY_UPSTREAM_USE_TLS): %t", upstreamUseTLS)
	log.Printf("跳过上游证书验证 (PROXY_UPSTREAM_INSECURE_SKIP_VERIFY): %t", upstreamInsecureSkipVerify)
	log.Printf("证书文件 (PROXY_CERT_FILE): %s", certFile)
	log.Printf("密钥文件 (PROXY_KEY_FILE): %s", keyFile)
	log.Println("-----------------")
}

// getEnv 从环境变量中获取一个值，如果环境变量未设置，则返回指定的默认值。
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getEnvBool 从环境变量中获取一个布尔值。
// "true", "1", "yes" 等值会被解析为 true。如果未设置或解析失败，则返回默认值。
func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		val, err := strconv.ParseBool(strings.ToLower(value))
		if err == nil {
			return val
		}
	}
	return fallback
}

func main() {
	// 加载我们为STARTTLS生成的自签名证书
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("无法加载证书/密钥对: %s", err)
	}

	// 创建服务器端的TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cer},
	}

	// 在指定地址上开始监听TCP连接
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("无法在 %s 上监听: %s", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("SMTP 代理正在监听 %s，并将请求转发到 %s", listenAddr, upstreamAddr)

	// 无限循环，等待并接受新的客户端连接
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受新连接失败: %s", err)
			continue
		}
		// 为每个连接创建一个新的goroutine来处理，避免阻塞主循环
		go handleConnection(conn, tlsConfig)
	}
}

// handleConnection负责处理单个客户端的完整生命周期
func handleConnection(clientConn net.Conn, localTlsConfig *tls.Config) {
	// 使用defer确保无论函数如何退出，连接都会被关闭
	defer clientConn.Close()
	log.Printf("接受来自 %s 的连接", clientConn.RemoteAddr())

	var upstreamConn net.Conn
	var err error

	// 根据配置连接到上游服务器
	if upstreamUseTLS {
		// 创建一个到上游的加密TLS连接
		// 在生产环境中，不应使用 InsecureSkipVerify: true
		// 您应该确保系统信任上游服务器的证书
		upstreamConn, err = tls.Dial("tcp", upstreamAddr, &tls.Config{
			// ServerName 用于 SNI (服务器名称指示)，这对于很多托管服务是必需的
			ServerName:         strings.Split(upstreamAddr, ":")[0],
			InsecureSkipVerify: upstreamInsecureSkipVerify,
		})
	} else {
		// 创建一个到上游的普通TCP连接
		upstreamConn, err = net.Dial("tcp", upstreamAddr)
	}

	if err != nil {
		log.Printf("连接上游服务器 %s 失败: %s", upstreamAddr, err)
		// 向客户端发送一个错误信息
		fmt.Fprintf(clientConn, "421 服务不可用，无法连接到上游服务器\r\n")
		return
	}
	defer upstreamConn.Close()
	log.Printf("成功连接到上游服务器 %s", upstreamAddr)

	// 从上游服务器读取初始的欢迎信息
	upstreamReader := bufio.NewReader(upstreamConn)
	greeting, err := upstreamReader.ReadString('\n')
	if err != nil {
		log.Printf("从上游读取欢迎信息失败: %s", err)
		return
	}
	// 将欢迎信息转发给客户端
	fmt.Fprint(clientConn, greeting)
	log.Printf("S->C: %s", strings.TrimSpace(greeting))

	clientReader := bufio.NewReader(clientConn)

	// 在TLS握手前，循环处理客户端命令
	for {
		clientCmd, err := clientReader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("从 %s 读取命令失败: %s", clientConn.RemoteAddr(), err)
			} else {
				log.Printf("来自 %s 的连接在命令阶段关闭", clientConn.RemoteAddr())
			}
			return
		}

		log.Printf("C->Proxy: %s", strings.TrimSpace(clientCmd))

		// 关键步骤：检查客户端是否请求STARTTLS
		if strings.ToUpper(strings.TrimSpace(clientCmd)) == "STARTTLS" {
			// 当客户端请求STARTTLS时，代理也必须与上游服务器协商STARTTLS

			// 1. 向客户端确认，准备开始TLS
			fmt.Fprint(clientConn, "220 Ready to start TLS\r\n")
			log.Printf("Proxy->C: 220 Ready to start TLS")

			// 2. 将与客户端的连接升级为TLS
			tlsClientConn := tls.Server(clientConn, localTlsConfig)
			if err := tlsClientConn.Handshake(); err != nil {
				log.Printf("与客户端的TLS握手失败: %s", err)
				return
			}
			log.Println("与客户端的连接已成功升级到TLS")

			// 3. 用升级后的TLS连接替换原始连接
			clientConn = tlsClientConn
			clientReader = bufio.NewReader(clientConn) // 读取器也需要更新

			// 4. 与上游服务器执行STARTTLS
			// 注意：此时我们不能假设上游服务器支持STARTTLS，需要先进行 EHLO/HELO
			// 为了简化，我们假设客户端会在STARTTLS后立即发送一个新的EHLO，
			// 这个EHLO将被透明地转发到上游，上游的响应也会包含STARTTLS。
			// 实际上，更健壮的代理会自己管理与上游的状态。
			// 这里的逻辑是：客户端升级后，代理就进入透明转发模式。
			// 客户端接下来发送的任何命令（如 EHLO, STARTTLS, AUTH）都会被直接转发。
			// 所以，我们需要让客户端再次发起STARTTLS，或者我们主动发起。

			// 我们在这里主动向上游发起 STARTTLS
			fmt.Fprint(upstreamConn, "STARTTLS\r\n")
			log.Printf("Proxy->S: STARTTLS")
			upstreamResp, err := readSmtpResponse(upstreamReader)
			if err != nil {
				log.Printf("从上游读取STARTTLS响应时出错: %s", err)
				return
			}
			log.Printf("S->Proxy: %s", strings.TrimSpace(upstreamResp))

			if !strings.HasPrefix(upstreamResp, "220") {
				log.Printf("上游服务器拒绝STARTTLS, 响应: %s", upstreamResp)
				// 将上游的错误信息转发给客户端
				fmt.Fprint(clientConn, upstreamResp)
				return
			}

			// 5. 将与上游的连接也升级为TLS
			tlsUpstreamConn := tls.Client(upstreamConn, &tls.Config{
				ServerName:         strings.Split(upstreamAddr, ":")[0],
				InsecureSkipVerify: upstreamInsecureSkipVerify,
			})
			// 手动执行握手，以确认连接成功
			if err := tlsUpstreamConn.Handshake(); err != nil {
				log.Printf("与上游服务器的TLS握手失败: %s", err)
				return
			}

			log.Println("与上游服务器的连接已成功升级到TLS")
			// 6. 用升级后的连接替换原始连接
			upstreamConn = tlsUpstreamConn
			upstreamReader = bufio.NewReader(upstreamConn)

			// 7. 现在两个连接都是加密的了，退出命令处理循环，进入完全透明的代理模式
			break
		}

		// 如果不是STARTTLS，则将命令和响应在两端之间传递
		fmt.Fprint(upstreamConn, clientCmd)
		upstreamResp, err := readSmtpResponse(upstreamReader) // 使用新的多行读取函数
		if err != nil {
			log.Printf("从上游读取响应时出错: %s", err)
			return
		}
		fmt.Fprint(clientConn, upstreamResp)
		log.Printf("S->C: %s", strings.TrimSpace(upstreamResp))

		// 如果客户端发送QUIT，则结束会话
		if strings.ToUpper(strings.TrimSpace(clientCmd)) == "QUIT" {
			log.Printf("收到QUIT命令，关闭来自 %s 的连接", clientConn.RemoteAddr())
			return
		}
	}

	// 进入透明代理模式
	// 此时，客户端连接可能已经是TLS加密的了
	// 我们在两个连接之间双向拷贝数据
	log.Println("进入透明代理模式，双向转发数据")

	// 创建一个goroutine负责将数据从客户端拷贝到上游
	go func() {
		// 当这个拷贝操作结束时（通常是因为连接关闭），
		// defer确保上游连接也被关闭，这会使得下面的另一个拷贝操作也结束
		defer upstreamConn.Close()
		io.Copy(upstreamConn, clientConn)
	}()

	// 在主goroutine中，将数据从上游拷贝到客户端
	// 这个操作会阻塞，直到连接关闭
	io.Copy(clientConn, upstreamConn)

	log.Printf("关闭来自 %s 的连接", clientConn.RemoteAddr())
}

// readSmtpResponse 从 reader 中读取一个完整的 (可能是多行的) SMTP 响应。
// SMTP的多行响应以 "XXX-" 开始，最后一行以 "XXX " 开始。
func readSmtpResponse(reader *bufio.Reader) (string, error) {
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return response.String(), err
		}
		response.WriteString(line)
		// 检查一个响应是否结束的条件:
		// 1. 响应行长度必须大于等于4 (例如 "220\r\n")
		// 2. 第4个字符是空格 ' '
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	return response.String(), nil
}
