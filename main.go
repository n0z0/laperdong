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

// Struktur untuk melacak permintaan yang kita kirim
type activeRequest struct {
	mac    net.HardwareAddr
	sentAt time.Time
}

// generateRandomMAC menghasilkan sebuah MAC address acak yang valid.
func generateRandomMAC() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	buf[0] = (buf[0] & 0xFE) | 0x02
	return net.HardwareAddr(buf), nil
}

// getMACByIP mencari MAC address dari interface berdasarkan alamat IPnya.
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
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.Equal(targetIP) {
					return iface.HardwareAddr, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("tidak bisa menemukan MAC untuk IP %s", targetIP)
}

// listener adalah goroutine yang mendengarkan respons DHCPOFFER dari server.
// VERSI DEBUG
func listener(handle *pcap.Handle, activeReqs *sync.Map) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0
	for packet := range packetSource.Packets() {
		packetCount++
		// DEBUG: Cetak setiap 100 paket yang ditangkap agar tidak spam
		if packetCount%100 == 0 {
			fmt.Printf("[DEBUG] Listener telah menangkap %d paket...\n", packetCount)
		}

		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			continue // Bukan paket DHCP, lanjut ke paket berikutnya
		}

		dhcp, _ := dhcpLayer.(*layers.DHCPv4)
		fmt.Printf("[DEBUG] Menangkap paket DHCP! Op: %d, Xid: %d\n", dhcp.Operation, dhcp.Xid)

		// Kita hanya tertarik pada DHCPOFFER
		if dhcp.Operation == layers.DHCPOpReply && len(dhcp.Options) > 0 {
			msgTypeFound := false
			for _, opt := range dhcp.Options {
				if opt.Type == layers.DHCPOptMessageType && len(opt.Data) > 0 {
					if opt.Data[0] == byte(layers.DHCPMsgTypeOffer) {
						msgTypeFound = true
						break
					}
				}
			}

			if msgTypeFound {
				fmt.Printf("[DEBUG] Menemukan DHCPOFFER untuk Xid: %d\n", dhcp.Xid)
				if reqInterface, ok := activeReqs.Load(dhcp.Xid); ok {
					req := reqInterface.(activeRequest)
					fmt.Printf("\n>>> SUKSES! IP %s ditawarkan untuk MAC %s (Xid: %d) <<<\n", dhcp.YourClientIP, req.mac, dhcp.Xid)
					activeReqs.Delete(dhcp.Xid)
				} else {
					fmt.Printf("[DEBUG] DHCPOFFER dengan Xid %d tidak cocok dengan permintaan aktif.\n", dhcp.Xid)
				}
			}
		}
	}
}

func main() {
	// --- LANGKAH 1: PILIH INTERFACE ---
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
		fmt.Printf("    Nama: %s\n", device.Name)
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
	if len(selectedDevice.Addresses) > 0 {
		for _, addr := range selectedDevice.Addresses {
			if addr.IP.To4() != nil {
				selectedIP = addr.IP
				break
			}
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

	// --- LANGKAH 2: SIAPKAN HANDLE DAN GOROUTINE ---
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

	var activeRequests sync.Map
	go listener(listenerHandle, &activeRequests)

	fmt.Println("Memulai pengiriman DHCP Discover dan pendengaran DHCPOFFER...")
	fmt.Println("Tekan Ctrl+C untuk berhenti.")

	// --- LANGKAH 3: LOOP PENGIRIMAN ---
	requestCount := 0
	for {
		requestCount++
		clientMAC, err := generateRandomMAC()
		if err != nil {
			log.Printf("Gagal membuat MAC: %v", err)
			continue
		}

		xidBytes := make([]byte, 4)
		rand.Read(xidBytes)
		xid := binary.BigEndian.Uint32(xidBytes)

		activeRequests.Store(xid, activeRequest{mac: clientMAC, sentAt: time.Now()})
		fmt.Printf("[%d] Mengirim DHCP Discover dari MAC: %s (Xid: %d)\n", requestCount, clientMAC, xid)

		// --- Bagian yang DIUBAH (SOLUSI 2: RAW BYTES - PALING AMPUH) ---
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
		udpLayer := &layers.UDP{
			SrcPort: 68,
			DstPort: 67,
		}
		udpLayer.SetNetworkLayerForChecksum(ipLayer)

		// --- Buat payload DHCP secara manual sebagai byte slice ---
		// Ini adalah struktur paket DHCP yang sebenarnya
		payload := make([]byte, 240+9) // 240 byte header + 9 byte untuk opsi-opsi kita

		// Header DHCP (offset 0-239)
		payload[0] = 1 // Op: Request
		payload[1] = 1 // Htype: Ethernet
		payload[2] = 6 // Hlen: 6 bytes for MAC
		payload[3] = 0 // Hops

		// Xid (Transaction ID) pada offset 4-7
		binary.BigEndian.PutUint32(payload[4:8], xid)

		// Secs (8-9) & Flags (10-11)
		binary.BigEndian.PutUint16(payload[8:10], 0)       // Secs
		binary.BigEndian.PutUint16(payload[10:12], 0x8000) // Flags: Broadcast

		// IP addresses (12-27) semua diisi 0
		// Client IP, Your Client IP, Next Server IP, Relay Agent IP

		// Client MAC Address (28-43), hanya 6 byte pertama yang dipakai
		copy(payload[28:34], clientMAC)
		// sisanya (sname, file) sudah otomatis 0

		// Magic Cookie pada offset 236-239
		binary.BigEndian.PutUint32(payload[236:240], 0x63825363)

		// Opsi-opsi DHCP (dimulai dari offset 240)
		payload[240] = 53  // Message Type option
		payload[241] = 1   // Length
		payload[242] = 1   // DHCP Discover
		payload[243] = 55  // Parameter Request List
		payload[244] = 3   // Length
		payload[245] = 1   // Subnet Mask
		payload[246] = 3   // Router
		payload[247] = 6   // DNS Server
		payload[248] = 255 // End Option

		// --- Kirim Paket ---
		// Kita gunakan gopacket.Payload untuk membungkus byte array kita
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, udpLayer, gopacket.Payload(payload))

		if err := senderHandle.WritePacketData(buf.Bytes()); err != nil {
			log.Printf("Gagal mengirim paket: %v", err)
		}

		time.Sleep(100 * time.Millisecond)
	}
}
