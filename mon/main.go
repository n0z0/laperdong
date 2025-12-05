package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Monitor DHCP interfaces and show live status
func main() {
	if os.Getuid() != 0 {
		log.Fatal("This program must be run as root")
	}

	fmt.Println("=== DHCP Multi-Lease Monitor ===")
	fmt.Println("Monitoring eth0:* interfaces (Ctrl+C to exit)")
	fmt.Println()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			showStatus()
		}
	}
}

func showStatus() {
	// Clear screen
	fmt.Print("\033[H\033[2J")

	fmt.Printf("=== DHCP Multi-Lease Status ===\n")
	fmt.Printf("Time: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// Get all interfaces
	cmd := exec.Command("ip", "link", "show")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error getting interface list: %v\n", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	eth0Interfaces := []string{}

	// Find all eth0:* interfaces
	for _, line := range lines {
		if strings.Contains(line, "eth0:") {
			parts := strings.Split(line, ":")
			if len(parts) > 0 {
				ifaceName := strings.TrimSpace(parts[0])
				if strings.Contains(ifaceName, "@") {
					ifaceName = strings.Split(ifaceName, "@")[0]
				}
				eth0Interfaces = append(eth0Interfaces, ifaceName)
			}
		}
	}

	if len(eth0Interfaces) == 0 {
		fmt.Println("No eth0:* interfaces found")
		return
	}

	fmt.Printf("Found %d DHCP interfaces:\n\n", len(eth0Interfaces))
	fmt.Println("Interface         MAC Address         Status     IP Address")
	fmt.Println(strings.Repeat("-", 70))

	// Get details for each interface
	for _, iface := range eth0Interfaces {
		// Get MAC address
		cmd := exec.Command("ip", "link", "show", iface)
		output, _ := cmd.Output()
		outputStr := string(output)

		// Extract MAC address
		mac := "N/A"
		if strings.Contains(outputStr, "link/ether") {
			parts := strings.Split(outputStr, "link/ether")
			if len(parts) > 1 {
				macParts := strings.Fields(parts[1])
				if len(macParts) > 0 {
					mac = macParts[0]
				}
			}
		}

		// Get IP address
		cmd = exec.Command("ip", "addr", "show", iface)
		ipOutput, _ := cmd.Output()
		ipOutputStr := string(ipOutput)

		ipAddress := "No IP"
		if strings.Contains(ipOutputStr, "inet ") {
			// Find inet line
			ipLines := strings.Split(ipOutputStr, "\n")
			for _, ipLine := range ipLines {
				if strings.Contains(ipLine, "inet ") {
					parts := strings.Fields(ipLine)
					if len(parts) >= 2 {
						ipAddress = parts[1]
						break
					}
				}
			}
		}

		// Get status
		status := "active"
		if strings.Contains(ipOutputStr, "UP") {
			status = "UP"
		}

		// Get PID of DHCP client if running
		cmd = exec.Command("pgrep", "-f", fmt.Sprintf("dhclient.*%s", iface))
		pidOutput, _ := cmd.Output()
		if len(pidOutput) == 0 {
			status = "no DHCP"
		}

		fmt.Printf("%-17s %-17s %-9s %s\n", iface, mac, status, ipAddress)
	}

	// Show summary
	fmt.Println(strings.Repeat("-", 70))

	activeCount := 0
	for _, iface := range eth0Interfaces {
		cmd = exec.Command("ip", "addr", "show", iface)
		ipOutput, _ := cmd.Output()
		if strings.Contains(string(ipOutput), "inet ") {
			activeCount++
		}
	}

	fmt.Printf("Total interfaces: %d, Active with IP: %d\n", len(eth0Interfaces), activeCount)
}
