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
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

var activeConnections int32 // 用于跟踪活跃连接的数量

func main() {
	// 解析命令行参数
	localAddr := flag.String("src", "0.0.0.0:1234", "本地监听的 IP 和端口")
	forwardAddrs := flag.String("dst", "127.0.0.1:4321", "转发的目标 IP 和端口,多目标模式用逗号分隔(第一个是非TLS地址,第二个是TLS地址,多出部分地址无效)")
	cidrs := flag.String("cidr", "0.0.0.0/0,::/0", "允许的来源 IP 范围 (CIDR),多个范围用逗号分隔")
	domainList := flag.String("domain", "*", "允许的域名列表,用逗号分隔,支持通配符*,默认转发所有域名")
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

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("读取连接数据时发生错误: %v", err)
		return
	}

	var forwardAddr string
	if n > 0 && buf[0] == 0x16 { // 判断是否是TLS握手开始的第一个字节
		// TLS 数据处理
		if len(destAddrs) >= 2 {
			forwardAddr = destAddrs[1] // 使用第二个地址
		} else if len(destAddrs) == 1 {
			forwardAddr = destAddrs[0] // 只有一个地址也可以使用
		} else {
			return
		}
		log.Printf("转发 TLS 数据到: %s", forwardAddr) // 显示转发地址
		handleHTTPS(conn, forwardAddr, allowedDomains, buf[:n])
	} else {
		// HTTP 数据处理
		if len(destAddrs) > 0 {
			forwardAddr = destAddrs[0]                 // 使用第一个地址
			log.Printf("转发 非TLS 数据到: %s", forwardAddr) // 显示转发地址
			handleHTTP(conn, forwardAddr, allowedDomains, buf[:n])
		} else {
			return
		}
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
	clientHello, fullHello, err := readClientHello(conn, initialData)
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

	// 将完整 ClientHello 发送给目标服务器
	_, err = forwardConn.Write(fullHello)
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
	if len(allowedDomains) == 1 && allowedDomains[0] == "*" {
		return true
	}

	for _, pattern := range allowedDomains {
		if matchDomain(host, pattern) {
			return true
		}
	}

	return false
}

func matchDomain(host, pattern string) bool {
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

func readClientHello(conn net.Conn, firstChunk []byte) (*tls.ClientHelloInfo, []byte, error) {
	buf := append([]byte(nil), firstChunk...)

	// 至少拿到记录层头部
	if len(buf) < 5 {
		if err := readN(conn, &buf, 5-len(buf)); err != nil {
			log.Printf("读取 ClientHello 记录头部失败: %v", err)
			return nil, nil, err
		}
	}
	// 解析记录长度
	recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	totalLen := 5 + recordLen
	if recordLen == 0 {
		log.Printf("ClientHello 记录长度为0")
		return nil, nil, fmt.Errorf("record length = 0")
	}
	// 继续读到完整记录
	if len(buf) < totalLen {
		if err := readN(conn, &buf, totalLen-len(buf)); err != nil {
			log.Printf("读取完整 ClientHello 失败: %v", err)
			return nil, nil, err
		}
	}

	// 现在 buf 中握手层完整
	hello := &tls.ClientHelloInfo{}
	r := bytes.NewReader(buf[5:]) // 跳过记录头

	var handshakeType uint8
	if err := binary.Read(r, binary.BigEndian, &handshakeType); err != nil {
		log.Printf("读取 Handshake 类型失败: %v", err)
		return nil, nil, err
	}
	if handshakeType != 1 { // 1 = client_hello
		log.Printf("不是 ClientHello 类型: %d", handshakeType)
		return nil, nil, fmt.Errorf("不是 ClientHello")
	}
	// 跳过长度 3
	r.Seek(3, io.SeekCurrent)
	// 跳过版本(2) + 随机数(32)
	r.Seek(34, io.SeekCurrent)

	// SessionID
	var sidLen uint8
	binary.Read(r, binary.BigEndian, &sidLen)
	r.Seek(int64(sidLen), io.SeekCurrent)

	// CipherSuites
	var csLen uint16
	binary.Read(r, binary.BigEndian, &csLen)
	r.Seek(int64(csLen), io.SeekCurrent)

	// Compression
	var compLen uint8
	binary.Read(r, binary.BigEndian, &compLen)
	r.Seek(int64(compLen), io.SeekCurrent)

	// Extensions
	var extLen uint16
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		log.Printf("读取扩展长度失败: %v", err)
		return nil, nil, err
	}
	extData := make([]byte, extLen)
	if _, err := io.ReadFull(r, extData); err != nil {
		log.Printf("读取扩展数据失败: %v", err)
		return nil, nil, err
	}

	for pos := 0; pos+4 <= len(extData); {
		etype := binary.BigEndian.Uint16(extData[pos : pos+2])
		el := binary.BigEndian.Uint16(extData[pos+2 : pos+4])
		if pos+4+int(el) > len(extData) {
			break
		}
		if etype == 0 { // SNI
			list := extData[pos+4 : pos+4+int(el)]
			if len(list) < 2 {
				break
			}
			listLen := binary.BigEndian.Uint16(list[:2])
			if int(listLen)+2 > len(list) || listLen == 0 {
				break
			}
			item := list[2:]
			if len(item) < 3 || item[0] != 0 {
				break
			}
			nameLen := binary.BigEndian.Uint16(item[1:3])
			if int(nameLen)+3 > len(item) {
				break
			}
			hello.ServerName = string(item[3 : 3+nameLen])
			log.Printf("解析到 SNI: %s", hello.ServerName)
			return hello, buf, nil
		}
		pos += 4 + int(el)
	}
	log.Printf("未找到 SNI")
	return hello, buf, fmt.Errorf("未找到 SNI")
}

func readN(conn net.Conn, dst *[]byte, n int) error {
	tmp := make([]byte, n)
	_, err := io.ReadFull(conn, tmp)
	if err != nil {
		return err
	}
	*dst = append(*dst, tmp...)
	return nil
}
