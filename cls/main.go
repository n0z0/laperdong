package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// Quick cleanup utility for DHCP interfaces
func main() {
	if os.Getuid() != 0 {
		log.Fatal("This program must be run as root")
	}

	fmt.Println("=== DHCP Interface Cleanup Utility ===")

	// Get command line arguments
	args := os.Args[1:]

	if len(args) == 0 {
		// Show status
		fmt.Println("\nCurrent DHCP interfaces:")
		cmd := exec.Command("ip", "link", "show")
		output, err := cmd.Output()
		if err != nil {
			log.Printf("Error getting interface list: %v", err)
			return
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "eth0:") {
				fmt.Println(line)

				// Extract interface name
				parts := strings.Split(line, ":")
				if len(parts) > 0 {
					ifaceName := strings.TrimSpace(parts[0])
					if strings.Contains(ifaceName, "@") {
						ifaceName = strings.Split(ifaceName, "@")[0]
					}

					// Get IP for this interface
					cmd := exec.Command("ip", "addr", "show", ifaceName)
					ipOutput, _ := cmd.Output()
					if strings.Contains(string(ipOutput), "inet ") {
						fmt.Printf("  IP Address: %s", strings.TrimSpace(string(ipOutput)))
					}
					fmt.Println()
				}
			}
		}

		fmt.Println("\nUsage:")
		fmt.Println("  sudo ./dhcp_cleanup               # Show status")
		fmt.Println("  sudo ./dhcp_cleanup <interface>   # Remove specific interface")
		fmt.Println("  sudo ./dhcp_cleanup all           # Remove all eth0:* interfaces")
		return
	}

	// Handle specific commands
	if args[0] == "all" {
		// Remove all eth0:* interfaces
		cmd := exec.Command("ip", "link", "show")
		output, err := cmd.Output()
		if err != nil {
			log.Printf("Error getting interface list: %v", err)
			return
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "eth0:") {
				parts := strings.Split(line, ":")
				if len(parts) > 0 {
					ifaceName := strings.TrimSpace(parts[0])
					if strings.Contains(ifaceName, "@") {
						ifaceName = strings.Split(ifaceName, "@")[0]
					}

					fmt.Printf("Removing interface: %s\n", ifaceName)

					// Kill any DHCP client for this interface
					cmd := exec.Command("pkill", "-f", fmt.Sprintf("dhclient.*%s", ifaceName))
					cmd.Run()

					// Remove the interface
					cmd = exec.Command("ip", "link", "del", ifaceName)
					if err := cmd.Run(); err != nil {
						fmt.Printf("  Warning: Failed to remove %s: %v\n", ifaceName, err)
					} else {
						fmt.Printf("  Successfully removed %s\n", ifaceName)
					}
				}
			}
		}

		// Kill all DHCP clients
		cmd = exec.Command("pkill", "dhclient")
		cmd.Run()
		fmt.Println("All DHCP clients stopped")

	} else if len(args) >= 1 {
		// Remove specific interface
		interfaceName := args[0]

		fmt.Printf("Removing interface: %s\n", interfaceName)

		// Kill DHCP client
		cmd := exec.Command("pkill", "-f", fmt.Sprintf("dhclient.*%s", interfaceName))
		cmd.Run()

		// Remove interface
		cmd = exec.Command("ip", "link", "del", interfaceName)
		if err := cmd.Run(); err != nil {
			fmt.Printf("Error removing interface: %v\n", err)
		} else {
			fmt.Printf("Successfully removed %s\n", interfaceName)
		}
	}
}
