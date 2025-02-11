package visualizer

import (
	"fmt"

	"github.com/Volkiaa/nmap-terminal-viz/internal/nmap"
)

func getHostAddress(host nmap.Host) string {
	for _, addr := range host.Addresses {
		if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
			return addr.Addr
		}
	}
	return "N/A"
}

func formatServiceKey(serviceName, version string) string {
	if serviceName == "" {
		return "@"
	}
	return fmt.Sprintf("%s@%s", serviceName, version)
}

func printIPListsByPort(ipLists map[uint16][]string) {
	for port, ips := range ipLists {
		fmt.Printf("Port %d is open on the following IPs: %v\n", port, ips)
	}
}

func printIPListsByService(ipLists map[string][]string) {
	for service, ips := range ipLists {
		if service == "Undefined service" {
			fmt.Printf("Undefined service is running on the following IPs: %v\n", ips)
		} else {
			fmt.Printf("Service %s is running on the following IPs: %v\n", service, ips)
		}
	}
}
