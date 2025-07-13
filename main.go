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
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// --- 配置项 ---
// 这些变量现在是 var 而不是 const，以便可以从环境变量中覆盖
var (
	// SMTP Proxy
	listenAddr                 string
	upstreamAddr               string
	upstreamUseTLS             bool
	upstreamInsecureSkipVerify bool
	certFile                   string
	keyFile                    string

	// POP3 to IMAP Adapter
	pop3ListenAddr         string
	imapUpstreamAddr       string
	imapInsecureSkipVerify bool
)

func init() {
	// SMTP 配置
	listenAddr = getEnv("PROXY_LISTEN_ADDR", "0.0.0.0:2525")
	upstreamAddr = getEnv("PROXY_UPSTREAM_ADDR", "mail.cuhk.edu.cn:587")
	upstreamUseTLS = getEnvBool("PROXY_UPSTREAM_USE_TLS", false)
	upstreamInsecureSkipVerify = getEnvBool("PROXY_UPSTREAM_INSECURE_SKIP_VERIFY", true)
	certFile = getEnv("PROXY_CERT_FILE", "cert.pem")
	keyFile = getEnv("PROXY_KEY_FILE", "key.pem")

	// POP3-IMAP 配置
	pop3ListenAddr = getEnv("POP3_LISTEN_ADDR", "0.0.0.0:995")
	imapUpstreamAddr = getEnv("IMAP_UPSTREAM_ADDR", "mail.cuhk.edu.cn:143") // 143是IMAP默认端口, 用于STARTTLS
	imapInsecureSkipVerify = getEnvBool("IMAP_INSECURE_SKIP_VERIFY", true)

	log.Println("--- 配置加载 ---")
	log.Printf("SMTP 监听地址 (PROXY_LISTEN_ADDR): %s", listenAddr)
	log.Printf("SMTP 上游服务器 (PROXY_UPSTREAM_ADDR): %s", upstreamAddr)
	log.Printf("SMTP 跳过上游证书验证 (PROXY_UPSTREAM_INSECURE_SKIP_VERIFY): %t", upstreamInsecureSkipVerify)
	log.Printf("POP3 监听地址 (POP3_LISTEN_ADDR): %s", pop3ListenAddr)
	log.Printf("IMAP 上游服务器 (IMAP_UPSTREAM_ADDR): %s", imapUpstreamAddr)
	log.Printf("IMAP 跳过上游证书验证 (IMAP_INSECURE_SKIP_VERIFY): %t", imapInsecureSkipVerify)
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
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("无法加载证书/密钥对 (cert: %s, key: %s): %s", certFile, keyFile, err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}

	var wg sync.WaitGroup

	// 启动 SMTP 代理服务
	wg.Add(1)
	go func() {
		defer wg.Done()
		startSmtpProxy(tlsConfig)
	}()

	// 启动 POP3 到 IMAP 适配器服务
	wg.Add(1)
	go func() {
		defer wg.Done()
		startPop3Adapter(tlsConfig)
	}()

	// 等待所有服务结束（实际上会一直运行）
	wg.Wait()
}

// startSmtpProxy 启动并运行SMTP代理监听
func startSmtpProxy(tlsConfig *tls.Config) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("[SMTP] 无法在 %s 上监听: %s", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("[SMTP] 代理正在监听 %s", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[SMTP] 接受新连接失败: %s", err)
			continue
		}
		go handleSmtpConnection(conn, tlsConfig)
	}
}

// startPop3Adapter 启动并运行POP3适配器监听
func startPop3Adapter(tlsConfig *tls.Config) {
	listener, err := tls.Listen("tcp", pop3ListenAddr, tlsConfig)
	if err != nil {
		log.Fatalf("[POP3] 无法在 %s 上监听: %s", pop3ListenAddr, err)
	}
	defer listener.Close()
	log.Printf("[POP3] 适配器正在监听 %s (TLS enabled)", pop3ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[POP3] 接受新连接失败: %s", err)
			continue
		}
		go handlePop3Connection(conn)
	}
}

// handlePop3Connection 负责处理单个POP3客户端连接并将其转换为IMAP
func handlePop3Connection(clientConn net.Conn) {
	defer clientConn.Close()
	log.Printf("[POP3] 接受来自 %s 的连接", clientConn.RemoteAddr())

	clientReader := bufio.NewReader(clientConn)
	clientWriter := bufio.NewWriter(clientConn)

	respond := func(format string, args ...interface{}) {
		fmt.Fprintf(clientWriter, format+"\r\n", args...)
		clientWriter.Flush()
		log.Printf("[POP3] S->C: %s", fmt.Sprintf(format, args...))
	}
	respondErr := func(msg string) { respond("-ERR %s", msg) }
	respondOK := func(format string, args ...interface{}) { respond("+OK "+format, args...) }

	respondOK("POP3 to IMAP adapter ready")

	var imapClient *imapclient.Client
	var user, pass string

	// --- Authorization state ---
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			log.Printf("[POP3] 在认证阶段读取命令失败: %v", err)
			return
		}
		log.Printf("[POP3] C->S: %s", strings.TrimSpace(line))
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "USER":
			if len(parts) > 1 {
				user = parts[1]
				respondOK("User name accepted, password please")
			} else {
				respondErr("User name is empty")
			}
		case "PASS":
			if len(parts) > 1 {
				pass = parts[1]
			} else {
				respondErr("Password is empty")
				continue
			}

			// USER 和 PASS 都已收到，开始进行 IMAP 登录
			opts := imapclient.Options{
				TLSConfig: &tls.Config{
					ServerName:         strings.Split(imapUpstreamAddr, ":")[0],
					InsecureSkipVerify: imapInsecureSkipVerify,
				},
				DebugWriter: log.Writer(),
			}
			c, err := imapclient.DialStartTLS(imapUpstreamAddr, &opts)
			if err != nil {
				log.Printf("[IMAP] 连接失败: %v", err)
				respondErr("Cannot connect to upstream IMAP server")
				return
			}

			if err := c.Login(user, pass).Wait(); err != nil {
				log.Printf("[IMAP] 登录失败 for user %s: %v", user, err)
				respondErr("Authentication failed")
				c.Close() // 确保关闭连接
				return
			}

			imapClient = c
			log.Printf("[IMAP] 用户 %s 登录成功", user)
			// 认证成功, 退出认证循环，进入事务处理状态
			goto transactionLoop
		case "QUIT":
			respondOK("Bye")
			return
		default:
			respondErr("Unknown command during authorization")
		}
	}

transactionLoop:
	// --- Transaction state ---
	// 只有在认证成功后才会到达这里
	// defer imapClient.Logout().Wait() // defer Logout for the rest of the connection
	respondOK("Logged in")

	// --- 调试：列出所有文件夹 ---
	log.Println("[IMAP-DEBUG] 正在尝试列出邮箱文件夹...")
	listCmd := imapClient.List("", "*", nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		defer imapClient.Logout().Wait() // defer Logout for the rest of the connection
		log.Printf("[IMAP-DEBUG] LIST 命令失败: %v", err)
		respondErr("Failed to list mailboxes for debugging")
		return
	}
	log.Printf("[IMAP-DEBUG] 找到 %d 个邮箱:", len(mailboxes))
	for _, m := range mailboxes {
		log.Printf("[IMAP-DEBUG]  - 名称: %s, 属性: %v", m.Mailbox, m.Attrs)
	}
	log.Println("[IMAP-DEBUG] 邮箱列表显示完毕.")
	// --- 调试结束 ---

	// 必须以读写模式选择邮箱，才能执行删除操作
	if _, err := imapClient.Select("INBOX", nil).Wait(); err != nil {
		log.Printf("[IMAP] 选择INBOX失败: %v", err)
		respondErr("Failed to select INBOX")
		return
	}

	var uidsToDelete []imap.UID

	// 定义一个可复用的搜索条件：所有未被标记为删除的邮件
	nonDeletedCriteria := &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagDeleted}}

	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			defer imapClient.Logout().Wait() // defer Logout for the rest of the connection
			return
		}
		log.Printf("[POP3] C->S: %s", strings.TrimSpace(line))
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "STAT":
			// `STATUS` 命令的 SIZE 属性并非 IMAP 标准，Exchange 服务器不支持。
			// 因此，我们需要通过 `UID SEARCH` 获取所有邮件UID，然后 `FETCH` 它们的大小并求和。
			searchData, err := imapClient.UIDSearch(nonDeletedCriteria, nil).Wait()
			if err != nil {
				log.Printf("[IMAP] STAT search failed: %v", err)
				respondErr("Failed to get STAT (search)")
				continue
			}
			uids := searchData.AllUIDs()

			var totalSize int64 = 0
			if len(uids) > 0 {
				seqSet := new(imap.UIDSet)
				seqSet.AddNum(uids...)
				fetchOpts := &imap.FetchOptions{RFC822Size: true}
				fetchCmd := imapClient.Fetch(*seqSet, fetchOpts)

				for msg := fetchCmd.Next(); msg != nil; msg = fetchCmd.Next() {
					// 一条消息的 FETCH 响应可能包含多个数据项 (例如 UID 和 RFC822.SIZE)。
					// 我们需要遍历所有数据项来找到我们需要的那一个。
					for item := msg.Next(); item != nil; item = msg.Next() {
						if sizeItem, ok := item.(imapclient.FetchItemDataRFC822Size); ok {
							totalSize += int64(sizeItem.Size)
						}
					}
				}
				if err := fetchCmd.Close(); err != nil {
					// 即使关闭失败，我们可能也已经获取到了需要的数据，所以只记录日志
					log.Printf("[IMAP] STAT fetch command close error: %v", err)
				}
			}
			respondOK("%d %d", len(uids), totalSize)
		case "LIST":
			searchData, err := imapClient.UIDSearch(nonDeletedCriteria, nil).Wait()
			if err != nil {
				respondErr("Failed to search mailbox")
				continue
			}
			uids := searchData.AllUIDs()
			if len(uids) == 0 {
				respondOK("0 messages")
				respond(".")
				continue
			}

			respondOK("%d messages", len(uids))
			for i, uid := range uids {
				fetchCmd := imapClient.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{RFC822Size: true})
				msg := fetchCmd.Next()
				if msg == nil {
					respond("%d 0", i+1)
					continue
				}
				item, _ := msg.Next().(imapclient.FetchItemDataRFC822Size)
				respond("%d %d", i+1, item.Size)
				fetchCmd.Close()
			}
			respond(".")
		case "RETR":
			if len(parts) < 2 {
				respondErr("Message number required")
				continue
			}
			msgNum, err := strconv.Atoi(parts[1])
			if err != nil || msgNum <= 0 {
				respondErr("Invalid message number")
				continue
			}

			searchData, err := imapClient.UIDSearch(nonDeletedCriteria, nil).Wait()
			if err != nil {
				respondErr("Failed to search mailbox")
				continue
			}
			uids := searchData.AllUIDs()
			if msgNum > len(uids) {
				respondErr("No such message")
				continue
			}
			log.Printf("[IMAP] 找到 %d 封邮件", len(uids))
			targetUID := uids[msgNum-1]
			log.Printf("[IMAP] 找到目标邮件UID: %d", targetUID)

			seqSet := imap.UIDSetNum(targetUID)
			fetchOpts := &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}
			fetchCmd := imapClient.Fetch(seqSet, fetchOpts)

			msg := fetchCmd.Next()
			if msg == nil {
				respondErr("No such message")
				fetchCmd.Close()
				continue
			}

			var bodySection imapclient.FetchItemDataBodySection
			var foundBody bool
			for item := msg.Next(); item != nil; item = msg.Next() {
				if bs, ok := item.(imapclient.FetchItemDataBodySection); ok {
					bodySection = bs
					foundBody = true
					break // 已经找到邮件正文，可以退出内部循环
				}
			}

			if !foundBody {
				respondErr("Could not retrieve message body")
				fetchCmd.Close()
				continue
			}

			buf, err := io.ReadAll(bodySection.Literal)
			if err != nil {
				respondErr("Failed to read message body")
				fetchCmd.Close()
				continue
			}
			fetchCmd.Close()

			respondOK("%d octets", len(buf))
			clientWriter.Write(buf)
			clientWriter.WriteString("\r\n.\r\n")
			clientWriter.Flush()
		case "DELE":
			if len(parts) < 2 {
				respondErr("Message number required")
				continue
			}
			msgNum, err := strconv.Atoi(parts[1])
			if err != nil || msgNum <= 0 {
				respondErr("Invalid message number")
				continue
			}

			searchData, err := imapClient.UIDSearch(nonDeletedCriteria, nil).Wait()
			if err != nil {
				respondErr("Failed to search mailbox for DELE")
				continue
			}
			uids := searchData.AllUIDs()
			if msgNum > len(uids) {
				respondErr("No such message")
				continue
			}
			targetUID := uids[msgNum-1]

			// 检查是否已标记为删除，避免重复添加
			alreadyMarked := false
			for _, uid := range uidsToDelete {
				if uid == targetUID {
					alreadyMarked = true
					break
				}
			}
			if !alreadyMarked {
				uidsToDelete = append(uidsToDelete, targetUID)
			}
			respondOK("Message %d deleted", msgNum)
		case "RSET":
			uidsToDelete = nil // 清空待删除列表
			// 根据POP3规范，RSET的响应还应包括收件箱中的邮件数量
			searchData, err := imapClient.UIDSearch(nonDeletedCriteria, nil).Wait()
			if err != nil {
				respondErr("Failed to get message count for RSET")
				continue
			}
			respondOK("%d messages in maildrop", len(searchData.AllUIDs()))
		case "NOOP":
			respondOK("")
		case "QUIT":
			if len(uidsToDelete) > 0 {
				log.Printf("[IMAP] 准备永久删除 %d 封邮件...", len(uidsToDelete))

				seqSet := imap.UIDSetNum(uidsToDelete...)

				// 1. 将邮件标记为 \Deleted
				storeFlags := imap.StoreFlags{
					Op:     imap.StoreFlagsAdd,
					Silent: true,
					Flags:  []imap.Flag{imap.FlagDeleted},
				}
				if err := imapClient.Store(seqSet, &storeFlags, nil).Close(); err != nil {
					log.Printf("[IMAP] STORE 命令失败: %v", err)
				}

				// 2. 使用 EXPUNGE 命令永久删除带有 \Deleted 标记的邮件
				// if err := imapClient.Expunge().Close(); err != nil {
				// 	log.Printf("[IMAP] EXPUNGE 命令失败: %v", err)
				// }
			}
			respondOK("Bye")
			return
		default:
			respondErr("Unknown command")
		}
	}
}

// handleSmtpConnection 负责处理单个SMTP客户端的完整生命周期
func handleSmtpConnection(clientConn net.Conn, localTlsConfig *tls.Config) {
	// 使用defer确保无论函数如何退出，连接都会被关闭
	defer clientConn.Close()
	log.Printf("[SMTP] 接受来自 %s 的连接", clientConn.RemoteAddr())

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
		log.Printf("[SMTP] 连接上游服务器 %s 失败: %s", upstreamAddr, err)
		// 向客户端发送一个错误信息
		fmt.Fprintf(clientConn, "421 服务不可用，无法连接到上游服务器\r\n")
		return
	}
	defer upstreamConn.Close()
	log.Printf("[SMTP] 成功连接到上游服务器 %s", upstreamAddr)

	// 从上游服务器读取初始的欢迎信息
	upstreamReader := bufio.NewReader(upstreamConn)
	greeting, err := readSmtpResponse(upstreamReader)
	if err != nil {
		log.Printf("[SMTP] 从上游读取欢迎信息失败: %s", err)
		return
	}
	// 将欢迎信息转发给客户端
	fmt.Fprint(clientConn, greeting)
	log.Printf("[SMTP] S->C: %s", strings.TrimSpace(greeting))

	clientReader := bufio.NewReader(clientConn)

	// 在TLS握手前，循环处理客户端命令
	for {
		clientCmd, err := clientReader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[SMTP] 从 %s 读取命令失败: %s", clientConn.RemoteAddr(), err)
			} else {
				log.Printf("[SMTP] 来自 %s 的连接在命令阶段关闭", clientConn.RemoteAddr())
			}
			return
		}

		log.Printf("[SMTP] C->Proxy: %s", strings.TrimSpace(clientCmd))

		// 关键步骤：检查客户端是否请求STARTTLS
		if strings.ToUpper(strings.TrimSpace(clientCmd)) == "STARTTLS" {
			// 当客户端请求STARTTLS时，代理也必须与上游服务器协商STARTTLS

			// 1. 向客户端确认，准备开始TLS
			fmt.Fprint(clientConn, "220 Ready to start TLS\r\n")
			log.Printf("[SMTP] Proxy->C: 220 Ready to start TLS")

			// 2. 将与客户端的连接升级为TLS
			tlsClientConn := tls.Server(clientConn, localTlsConfig)
			if err := tlsClientConn.Handshake(); err != nil {
				log.Printf("[SMTP] 与客户端的TLS握手失败: %s", err)
				return
			}
			log.Println("[SMTP] 与客户端的连接已成功升级到TLS")

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
			log.Printf("[SMTP] Proxy->S: STARTTLS")
			upstreamResp, err := readSmtpResponse(upstreamReader)
			if err != nil {
				log.Printf("[SMTP] 从上游读取STARTTLS响应时出错: %s", err)
				return
			}
			log.Printf("[SMTP] S->Proxy: %s", strings.TrimSpace(upstreamResp))

			if !strings.HasPrefix(upstreamResp, "220") {
				log.Printf("[SMTP] 上游服务器拒绝STARTTLS, 响应: %s", upstreamResp)
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
				log.Printf("[SMTP] 与上游服务器的TLS握手失败: %s", err)
				return
			}

			log.Println("[SMTP] 与上游服务器的连接已成功升级到TLS")
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
			log.Printf("[SMTP] 从上游读取响应时出错: %s", err)
			return
		}
		fmt.Fprint(clientConn, upstreamResp)
		log.Printf("[SMTP] S->C: %s", strings.TrimSpace(upstreamResp))

		// 如果客户端发送QUIT，则结束会话
		if strings.ToUpper(strings.TrimSpace(clientCmd)) == "QUIT" {
			log.Printf("[SMTP] 收到QUIT命令，关闭来自 %s 的连接", clientConn.RemoteAddr())
			return
		}
	}

	// 进入透明代理模式
	// 此时，客户端连接可能已经是TLS加密的了
	// 我们在两个连接之间双向拷贝数据
	log.Println("[SMTP] 进入透明代理模式，双向转发数据")

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

	log.Printf("[SMTP] 关闭来自 %s 的连接", clientConn.RemoteAddr())
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
