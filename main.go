package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var activeConnections int32 // 用于跟踪活跃连接的数量

func main() {
	// 解析命令行参数
	localAddr := flag.String("src", "0.0.0.0:1234", "本地监听的 IP 和端口")
	forwardAddrs := flag.String("dst", "127.0.0.1:4321", "转发的目标 IP 和端口,用逗号分隔,域名匹配模式下(默认第一个是非TLS地址,第二个是TLS地址,多出地址不生效),TCP模式下随机转发")
	cidrs := flag.String("cidr", "0.0.0.0/0,::/0", "允许的来源 IP 范围 (CIDR),多个范围用逗号分隔")
	domainList := flag.String("domain", "*", "允许的域名列表,用逗号分隔,支持通配符,默认唯一参数*是TCP转发模式")
	flag.Parse()

	// 解析多个 CIDR 范围
	allowedNets := []*net.IPNet{}
	for _, cidr := range strings.Split(*cidrs, ",") {
		_, allowedNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("无法解析 CIDR: %v", err)
		}
		allowedNets = append(allowedNets, allowedNet)
	}

	// 解析允许的域名列表
	allowedDomains := strings.Split(*domainList, ",")

	// 解析多个目标地址
	destAddrs := strings.Split(*forwardAddrs, ",")

	// 监听本地地址
	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("无法监听 %s: %v", *localAddr, err)
	}
	defer listener.Close()
	log.Printf("正在监听 %s 并转发到 %v", *localAddr, destAddrs)

	for {
		// 接受客户端连接
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接时发生错误: %v", err)
			continue
		}

		// 检查来源IP是否在白名单内
		clientIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			log.Printf("无法解析客户端地址: %v", err)
			conn.Close()
			continue
		}

		clientIPAddr := net.ParseIP(clientIP)
		allowed := false
		for _, allowedNet := range allowedNets {
			if allowedNet.Contains(clientIPAddr) {
				allowed = true
				break
			}
		}

		if !allowed {
			log.Printf("拒绝访问: IP %s 不在允许的范围内 (%s)", clientIP, *cidrs)
			conn.Close()
			continue
		}

		// 增加活跃连接数
		atomic.AddInt32(&activeConnections, 1)
		log.Printf("允许访问: IP %s 在允许的范围内 (%s)", clientIP, *cidrs)
		log.Printf("新连接建立，当前活跃连接数: %d", atomic.LoadInt32(&activeConnections))

		// 处理连接
		go handleConnection(conn, destAddrs, allowedDomains)
	}
}

func handleConnection(conn net.Conn, destAddrs []string, allowedDomains []string) {
	defer func() {
		// 减少活跃连接数
		atomic.AddInt32(&activeConnections, -1)
		log.Printf("连接关闭，当前活跃连接数: %d", atomic.LoadInt32(&activeConnections))
		conn.Close()
	}()

	// 如果只有一个目标地址，无论是 TLS 还是非 TLS 数据，都转发到这个地址
	if len(destAddrs) == 1 {
		forwardAddr := destAddrs[0]
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("读取连接数据时发生错误: %v", err)
			return
		}

		if n > 0 && buf[0] == 0x16 { // 判断是否是TLS握手开始的第一个字节
			handleHTTPS(conn, forwardAddr, allowedDomains, buf[:n])
		} else {
			// 非 TLS 数据，无论如何都转发到唯一目标地址
			if len(destAddrs) > 1 && allowedDomains[0] == "*" {
				rand.Seed(time.Now().UnixNano())
				forwardAddr = destAddrs[rand.Intn(len(destAddrs))]
			}
			handleHTTP(conn, forwardAddr, allowedDomains, buf[:n])
		}
		return
	}

	// 读取前几个字节判断是否是TLS请求
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("读取连接数据时发生错误: %v", err)
		return
	}

	// 根据数据类型选择目标地址
	var forwardAddr string
	if n > 0 && buf[0] == 0x16 { // 判断是否是TLS握手开始的第一个字节
		// TLS 数据，使用第二个目标地址（如果存在）
		if len(destAddrs) < 2 {
			log.Printf("TLS 数据接收时目标地址不足")
			return
		}
		forwardAddr = destAddrs[1]
		handleHTTPS(conn, forwardAddr, allowedDomains, buf[:n])
	} else {
		// 非 TLS 数据，随机选择一个目标地址（如果有多个）
		if len(destAddrs) > 1 && allowedDomains[0] == "*" {
			rand.Seed(time.Now().UnixNano())
			forwardAddr = destAddrs[rand.Intn(len(destAddrs))]
		} else {
			forwardAddr = destAddrs[0]
		}
		handleHTTP(conn, forwardAddr, allowedDomains, buf[:n])
	}
}

func handleHTTP(conn net.Conn, forwardAddr string, allowedDomains []string, initialData []byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("读取 HTTP 请求时发生错误: %v", err)
		return
	}

	host := req.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	if !isAllowedDomain(host, allowedDomains) {
		log.Printf("拒绝访问: Host %s 不在允许的域名列表中", host)
		return
	}
	log.Printf("允许访问: Host %s 在允许的域名列表中", host)

	// 建立与目标服务器的连接并转发数据
	forwardConn, err := net.Dial("tcp", forwardAddr)
	if err != nil {
		log.Printf("无法连接到 %s: %v", forwardAddr, err)
		return
	}
	defer forwardConn.Close()

	// 将初始数据发送给目标服务器
	_, err = forwardConn.Write(initialData)
	if err != nil {
		log.Printf("向目标服务器发送初始数据时出错: %v", err)
		return
	}

	// 开始双向数据转发
	handleTCPForward(conn, forwardConn)
}

func handleHTTPS(conn net.Conn, forwardAddr string, allowedDomains []string, initialData []byte) {
	// 读取 TLS ClientHello 消息
	clientHello, err := readClientHello(initialData)
	if err != nil {
		log.Printf("读取 ClientHello 时发生错误: %v", err)
		return
	}

	// 验证 SNI
	sni := clientHello.ServerName
	if !isAllowedDomain(sni, allowedDomains) {
		log.Printf("拒绝访问: SNI %s 不在允许的域名列表中", sni)
		return
	}
	log.Printf("允许访问: SNI %s 在允许的域名列表中", sni)

	// 建立与目标服务器的连接
	forwardConn, err := net.Dial("tcp", forwardAddr)
	if err != nil {
		log.Printf("无法连接到 %s: %v", forwardAddr, err)
		return
	}
	defer forwardConn.Close()

	// 将初始数据发送给目标服务器
	_, err = forwardConn.Write(initialData)
	if err != nil {
		log.Printf("向目标服务器发送初始数据时出错: %v", err)
		return
	}

	// 开始双向数据转发
	handleTCPForward(conn, forwardConn)
}

func handleTCPForward(clientConn, serverConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(serverConn, clientConn)
		serverConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, serverConn)
		clientConn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

func isAllowedDomain(host string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 || (len(allowedDomains) == 1 && allowedDomains[0] == "*") {
		return true // 如果允许列表为空或只包含 "*"，则允许所有域名
	}

	for _, pattern := range allowedDomains {
		if pattern == "*" {
			return true // 允许所有域名
		}
		if matchDomain(host, pattern) {
			return true
		}
	}
	return false
}

func matchDomain(host, pattern string) bool {
	// 将模式转换为正则表达式
	regexPattern := strings.Replace(pattern, ".", "\\.", -1)
	regexPattern = strings.Replace(regexPattern, "*", ".*", -1)
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, host)
	if err != nil {
		log.Printf("域名匹配出错: %v", err)
		return false
	}
	return matched
}

func readClientHello(data []byte) (*tls.ClientHelloInfo, error) {
	reader := bytes.NewReader(data)
	hello := &tls.ClientHelloInfo{}

	// 跳过 TLS 记录层头部
	reader.Seek(5, io.SeekStart)

	// 读取 Handshake 消息类型
	var handshakeType uint8
	if err := binary.Read(reader, binary.BigEndian, &handshakeType); err != nil {
		return nil, err
	}

	// 确保是 ClientHello 消息
	if handshakeType != 1 {
		return nil, fmt.Errorf("不是 ClientHello 消息")
	}

	// 跳过 Handshake 消息长度
	reader.Seek(3, io.SeekCurrent)

	// 跳过协议版本和随机数
	reader.Seek(34, io.SeekCurrent)

	// 跳过 Session ID
	var sessionIDLength uint8
	binary.Read(reader, binary.BigEndian, &sessionIDLength)
	reader.Seek(int64(sessionIDLength), io.SeekCurrent)

	// 跳过密码套件
	var cipherSuitesLength uint16
	binary.Read(reader, binary.BigEndian, &cipherSuitesLength)
	reader.Seek(int64(cipherSuitesLength), io.SeekCurrent)

	// 跳过压缩方法
	var compressionMethodsLength uint8
	binary.Read(reader, binary.BigEndian, &compressionMethodsLength)
	reader.Seek(int64(compressionMethodsLength), io.SeekCurrent)

	// 读取扩展部分
	var extensionsLength uint16
	if err := binary.Read(reader, binary.BigEndian, &extensionsLength); err != nil {
		return nil, err
	}

	extensionsData := make([]byte, extensionsLength)
	if _, err := io.ReadFull(reader, extensionsData); err != nil {
		return nil, err
	}

	// 解析扩展以查找 SNI
	for len(extensionsData) > 4 {
		extensionType := binary.BigEndian.Uint16(extensionsData[:2])
		extensionLength := binary.BigEndian.Uint16(extensionsData[2:4])
		extensionData := extensionsData[4 : 4+extensionLength]

		if extensionType == 0 { // Server Name Indication
			if len(extensionData) > 2 {
				listLength := binary.BigEndian.Uint16(extensionData[:2])
				nameList := extensionData[2 : 2+listLength]
				if len(nameList) > 3 {
					nameType := nameList[0]
					if nameType == 0 { // host_name
						nameLength := binary.BigEndian.Uint16(nameList[1:3])
						if len(nameList) >= int(3+nameLength) {
							hello.ServerName = string(nameList[3 : 3+nameLength])
							return hello, nil
						}
					}
				}
			}
		}

		extensionsData = extensionsData[4+extensionLength:]
	}

	return hello, nil
}
