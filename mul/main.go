package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DHCPMultiLease manages multiple DHCP leases with unique MAC addresses
type DHCPMultiLease struct {
	Interface  string
	NumIPs     int
	BaseMAC    string
	Interfaces []VirtualInterface
	Mutex      sync.Mutex
}

// VirtualInterface represents a virtual network interface
type VirtualInterface struct {
	Name      string
	MAC       string
	PID       int
	Status    string
	IPAddress string
}

// NewDHCPMultiLease creates a new DHCP multi-lease manager
func NewDHCPMultiLease(interfaceName string, numIPs int) *DHCPMultiLease {
	return &DHCPMultiLease{
		Interface:  interfaceName,
		NumIPs:     numIPs,
		BaseMAC:    "02:42:ac:11:00:00",
		Interfaces: make([]VirtualInterface, numIPs),
	}
}

// generateUniqueMAC generates a unique MAC address based on index
func (d *DHCPMultiLease) generateUniqueMAC(index int) string {
	// Convert index to hex for MAC generation
	high := fmt.Sprintf("%02x", index/256)
	low := fmt.Sprintf("%02x", index%256)
	return fmt.Sprintf("02:42:ac:11:%s:%s", high, low)
}

// createVirtualInterface creates a virtual network interface with unique MAC
func (d *DHCPMultiLease) createVirtualInterface(index int) error {
	virtInterfaceName := fmt.Sprintf("%s:%d", d.Interface, index)
	mac := d.generateUniqueMAC(index)

	// Create virtual interface
	cmd := exec.Command("ip", "link", "add", "name", virtInterfaceName, "type", "dummy")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create interface %s: %v", virtInterfaceName, err)
	}

	// Set MAC address
	cmd = exec.Command("ip", "link", "set", "dev", virtInterfaceName, "address", mac)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MAC address for %s: %v", virtInterfaceName, err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", virtInterfaceName, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface %s: %v", virtInterfaceName, err)
	}

	// Update interface info
	d.Mutex.Lock()
	d.Interfaces[index] = VirtualInterface{
		Name:   virtInterfaceName,
		MAC:    mac,
		Status: "created",
	}
	d.Mutex.Unlock()

	log.Printf("Created interface %s with MAC %s", virtInterfaceName, mac)
	return nil
}

// startDHCPClient starts DHCP client for a specific interface
func (d *DHCPMultiLease) startDHCPClient(index int) error {
	d.Mutex.Lock()
	virtInterface := d.Interfaces[index]
	d.Mutex.Unlock()

	// Start DHCP client with process tracking
	cmd := exec.Command("dhclient", "-pf",
		fmt.Sprintf("/var/run/dhclient-%s.pid", virtInterface.Name),
		"-lf", fmt.Sprintf("/var/lib/dhcp/dhclient-%s.leases", virtInterface.Name),
		"-v", virtInterface.Name)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start DHCP client for %s: %v", virtInterface.Name, err)
	}

	// Update status
	d.Mutex.Lock()
	d.Interfaces[index].PID = cmd.Process.Pid
	d.Interfaces[index].Status = "dhcp_requested"
	d.Mutex.Unlock()

	log.Printf("Started DHCP client for %s (PID: %d)", virtInterface.Name, cmd.Process.Pid)
	return nil
}

// setupMultipleDHCP setups all virtual interfaces and DHCP clients
func (d *DHCPMultiLease) setupMultipleDHCP() error {
	log.Printf("Setting up %d DHCP leases on interface %s", d.NumIPs, d.Interface)

	// Create all virtual interfaces
	for i := 0; i < d.NumIPs; i++ {
		if err := d.createVirtualInterface(i); err != nil {
			log.Printf("Error creating interface %d: %v", i, err)
			return err
		}
		time.Sleep(100 * time.Millisecond) // Small delay to avoid conflicts
	}

	// Start DHCP clients with some delay between each
	for i := 0; i < d.NumIPs; i++ {
		if err := d.startDHCPClient(i); err != nil {
			log.Printf("Error starting DHCP client %d: %v", i, err)
			// Continue with other interfaces even if one fails
		}
		time.Sleep(500 * time.Millisecond) // Delay between DHCP requests
	}

	log.Println("DHCP setup completed. Waiting for IP assignments...")
	time.Sleep(10 * time.Second) // Wait for DHCP to complete
	return nil
}

// getInterfaceIP gets the IP address assigned to an interface
func (d *DHCPMultiLease) getInterfaceIP(interfaceName string) (string, error) {
	cmd := exec.Command("ip", "addr", "show", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse IP address from output
	lines := string(output)
	start := -1
	for i, char := range lines {
		if char == 'i' && i+3 < len(lines) && lines[i:i+4] == "inet" {
			start = i + 5
			break
		}
	}

	if start == -1 {
		return "No IP", nil
	}

	end := start
	for end < len(lines) && (lines[end] >= '0' && lines[end] <= '9' || lines[end] == '.' || lines[end] == '/') {
		end++
	}

	return lines[start:end], nil
}

// monitorIPAssignments monitors and displays current IP assignments
func (d *DHCPMultiLease) monitorIPAssignments() {
	fmt.Println("\n=== Current IP Assignments ===")
	for i, v := range d.Interfaces {
		ip, _ := d.getInterfaceIP(v.Name)
		d.Mutex.Lock()
		d.Interfaces[i].IPAddress = ip
		d.Mutex.Unlock()

		fmt.Printf("Interface: %-10s MAC: %-17s IP: %-15s Status: %s\n",
			v.Name, v.MAC, ip, v.Status)
	}
}

// showStatus shows detailed status of all interfaces
func (d *DHCPMultiLease) showStatus() {
	fmt.Println("\n=== DHCP Multi-Lease Status ===")
	fmt.Printf("Base Interface: %s\n", d.Interface)
	fmt.Printf("Number of IPs: %d\n", d.NumIPs)
	fmt.Printf("Timestamp: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	fmt.Println("Interface Details:")
	fmt.Println("Name              MAC Address         PID    Status          IP Address")
	fmt.Println(strings.Repeat("-", 75))

	d.Mutex.Lock()
	for _, v := range d.Interfaces {
		fmt.Printf("%-17s %-17s %-6d %-15s %-15s\n",
			v.Name, v.MAC, v.PID, v.Status, v.IPAddress)
	}
	d.Mutex.Unlock()
}

// cleanupInterface removes a specific virtual interface
func (d *DHCPMultiLease) cleanupInterface(index int) error {
	d.Mutex.Lock()
	virtInterface := d.Interfaces[index]
	d.Mutex.Unlock()

	// Kill DHCP client
	if virtInterface.PID > 0 {
		cmd := exec.Command("kill", strconv.Itoa(virtInterface.PID))
		cmd.Run()
		log.Printf("Killed DHCP client for %s (PID: %d)", virtInterface.Name, virtInterface.PID)
	}

	// Remove interface
	cmd := exec.Command("ip", "link", "del", virtInterface.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove interface %s: %v", virtInterface.Name, err)
	}

	log.Printf("Removed interface %s", virtInterface.Name)
	return nil
}

// cleanupAll removes all virtual interfaces and stops DHCP clients
func (d *DHCPMultiLease) cleanupAll() {
	log.Println("Starting cleanup of all DHCP interfaces...")

	// Kill all DHCP clients
	cmd := exec.Command("pkill", "dhclient")
	cmd.Run()

	// Remove all virtual interfaces
	for i := 0; i < d.NumIPs; i++ {
		d.cleanupInterface(i)
	}

	// Clear interface list
	d.Mutex.Lock()
	d.Interfaces = make([]VirtualInterface, 0)
	d.Mutex.Unlock()

	log.Println("Cleanup completed")
}

// TestConnectivity tests connectivity for each IP
func (d *DHCPMultiLease) TestConnectivity() {
	fmt.Println("\n=== Connectivity Test ===")

	for _, v := range d.Interfaces {
		if v.IPAddress != "No IP" && v.IPAddress != "" {
			// Test ping to gateway (you may need to adjust this)
			cmd := exec.Command("ping", "-c", "1", "-W", "2", "8.8.8.8")
			cmd.Run() // We ignore errors as we just want to see if IP is active
			fmt.Printf("Testing %s (%s)...\n", v.Name, v.IPAddress)
		}
	}
}

func main() {
	// Check if running as root
	if os.Getuid() != 0 {
		log.Fatal("This program must be run as root")
	}

	// Configuration
	interfaceName := "eth0"
	numIPs := 10

	// Create DHCP manager
	dhcp := NewDHCPMultiLease(interfaceName, numIPs)

	// Handle cleanup on exit
	defer dhcp.cleanupAll()

	// Setup and run
	fmt.Println("=== DHCP Multiple Lease Setup ===")
	fmt.Printf("Interface: %s, Number of IPs: %d\n", interfaceName, numIPs)

	if err := dhcp.setupMultipleDHCP(); err != nil {
		log.Printf("Setup failed: %v", err)
		return
	}

	// Show status and monitor
	dhcp.showStatus()
	dhcp.monitorIPAssignments()

	// Wait and monitor for a while
	fmt.Println("\nMonitoring for 30 seconds...")
	for i := 0; i < 6; i++ {
		time.Sleep(5 * time.Second)
		dhcp.monitorIPAssignments()
	}

	// Test connectivity
	dhcp.TestConnectivity()

	fmt.Println("\n=== Setup Complete ===")
	fmt.Println("Use Ctrl+C to cleanup and exit")

	// Keep running and monitoring
	for {
		time.Sleep(30 * time.Second)
		dhcp.monitorIPAssignments()
	}
}
