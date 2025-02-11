package visualizer

import (
	"fmt"
	"os"
	"strings"

	"github.com/Volkiaa/nmap-terminal-viz/internal/nmap"
	"github.com/Volkiaa/nmap-terminal-viz/internal/cveCheck"
	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

const barWidth = 40

var (
	green  = color.New(color.FgGreen)
	red    = color.New(color.FgRed)
	yellow = color.New(color.FgYellow)
	magenta   = color.New(color.FgMagenta, color.Bold)
)

var stateColors = map[string]*color.Color{
	"open":     green,
	"closed":   red,
	"filtered": yellow,
}

func Display(result *nmap.ScanResult) (map[uint16][]string, map[string][]string) {
	ports := aggregatePortData(result)
	total := totalPorts(ports)

	// Show progress bars
	for state, count := range ports {
		createProgressBar(state, count, total)
	}

	// Show port/service table
	renderPortTable(result)

	// Categorize hosts by ports and services
	ipListsByPort, ipListsByService := categorizeHostsByPortsAndServices(result)

	// Save the lists of IPs by service to files
	saveIPListsByService(ipListsByService)

	// Return the lists of IPs by port and service
	return ipListsByPort, ipListsByService
}

func categorizeHostsByPortsAndServices(result *nmap.ScanResult) (map[uint16][]string, map[string][]string) {
	ipListsByPort := make(map[uint16][]string)
	ipListsByService := make(map[string][]string)

	for _, host := range result.Hosts {
		hostAddress := getHostAddress(host)
		for _, port := range host.Ports {
			ipListsByPort[port.PortID] = append(ipListsByPort[port.PortID], hostAddress)
			serviceKey := formatServiceKey(port.Service.Name, port.Service.Version)
			if serviceKey == "@" {
				serviceKey = "Undefined service"
			}
			ipListsByService[serviceKey] = append(ipListsByService[serviceKey], hostAddress)
		}
	}

	printIPListsByPort(ipListsByPort)
	printIPListsByService(ipListsByService)

	return ipListsByPort, ipListsByService
}

func renderPortTable(result *nmap.ScanResult) {
	fmt.Println("\nPort/Service Details ")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Port", "Protocol", "State", "Service", "Application", "Version", "CVEs", "Most Critical CVE"})
	table.SetBorder(false)
	table.SetAutoWrapText(false)

	for _, host := range result.Hosts {
		hostAddress := getHostAddress(host)
		for _, port := range host.Ports {
			stateColor := stateColors[port.State.State]
			cves, criticalCVE := cvechecker.FetchCVEs(port.Service.Product, port.Service.Version)
			cveList := strings.Join(cves, ", ")

			row := []string{
				fmt.Sprintf("%d", port.PortID),
				port.Protocol,
				stateColor.Sprintf(port.State.State),
				port.Service.Name,
				port.Service.Product,
				port.Service.Version,
				fmt.Sprintf("%d", len(cveList)),
				criticalCVE,
			}
			table.Append(row)
		}
		magenta.Println("Details for ", hostAddress)
	}
	table.Render()
}

func aggregatePortData(result *nmap.ScanResult) map[string]int {
	portCounts := make(map[string]int)
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			portCounts[port.State.State]++
		}
	}
	return portCounts
}

func totalPorts(ports map[string]int) int {
	total := 0
	for _, count := range ports {
		total += count
	}
	return total
}

func createProgressBar(state string, count, total int) {
	if total == 0 {
		return
	}

	colorFunc := stateColors[state].SprintFunc()
	template := fmt.Sprintf(`{{ cyan "%s" }} {{ bar . "%s" "█" (cycle . "%s") " " }} {{ percent . }} ({{ counters . }})`,
		strings.ToUpper(state),
		strings.Repeat(" ", barWidth),
		colorFunc("█"),
	)

	bar := pb.ProgressBarTemplate(template).Start(total)
	bar.SetCurrent(int64(count))
	bar.Finish()
}
