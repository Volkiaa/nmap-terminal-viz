package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// NmapRun represents the structure of an NMAP scan result
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Host    []Host   `xml:"host"`
}

// Host represents details of a scanned host
type Host struct {
	Addresses []Address `xml:"address"`
	Ports     Ports     `xml:"ports"`
	OS        OS        `xml:"os"`
}

// Address contains network address information
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// Ports contains information about open ports
type Ports struct {
	Port []Port `xml:"port"`
}

// Port represents details of an individual port
type Port struct {
	PortID   string  `xml:"portid,attr"`
	Protocol string  `xml:"protocol,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

// State represents the state of a port
type State struct {
	State string `xml:"state,attr"`
}

// Service contains service details for a port
type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
}

// OS contains operating system detection information
type OS struct {
	OSMatch []OSMatch `xml:"osmatch"`
}

// OSMatch represents potential OS matches
type OSMatch struct {
	Name     string  `xml:"name,attr"`
	Accuracy float64 `xml:"accuracy,attr"`
}

func main() {
	// Check if file path is provided
	if len(os.Args) < 2 {
		log.Fatal("Please provide an NMAP XML scan file")
	}

	// Get the input file path
	inputFile := os.Args[1]

	// Parse the NMAP XML file
	nmapRun, err := parseNmapXML(inputFile)
	if err != nil {
		log.Fatalf("Error parsing NMAP file: %v", err)
	}

	// Visualize the scan results
	visualizeNmapScan(nmapRun)
}

// parseNmapXML parses an NMAP XML file and extracts host information
func parseNmapXML(filepath string) (*NmapRun, error) {
	// Read entire file content
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	// Parse XML content
	var nmapRun NmapRun
	err = xml.Unmarshal(content, &nmapRun)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling XML: %v", err)
	}

	return &nmapRun, nil
}

// visualizeNmapScan creates an interactive terminal visualization
func visualizeNmapScan(nmapRun *NmapRun) {
	// Print scan summary
	printScanSummary(nmapRun)

	// Iterate through hosts and create detailed visualization
	for _, host := range nmapRun.Host {
		visualizeHost(host)
	}
}

// printScanSummary displays an overview of the entire scan
func printScanSummary(nmapRun *NmapRun) {
	// Use color for visual emphasis
	summaryTitle := color.New(color.FgWhite, color.Bold)
	summaryHighlight := color.New(color.FgCyan)

	summaryTitle.Println("\n🔍 NMAP Scan Summary 🔍")
	summaryHighlight.Printf("Total Hosts Scanned: %d\n", len(nmapRun.Host))

	// Count open ports across all hosts
	totalOpenPorts := 0
	for _, host := range nmapRun.Host {
		totalOpenPorts += countOpenPorts(host)
	}
	summaryHighlight.Printf("Total Open Ports: %d\n\n", totalOpenPorts)
}

// countOpenPorts counts the number of open ports for a host
func countOpenPorts(host Host) int {
	openPortCount := 0
	for _, port := range host.Ports.Port {
		if port.State.State == "open" {
			openPortCount++
		}
	}
	return openPortCount
}

// visualizeHost creates a detailed visualization for a single host
func visualizeHost(host Host) {
	// Use color for different sections
	hostTitle := color.New(color.FgGreen, color.Bold)
	addressColor := color.New(color.FgYellow)

	// Print host addresses
	hostTitle.Println("\n🖥️ Host Information")
	for _, addr := range host.Addresses {
		addressColor.Printf("  • %s (%s)\n", addr.Addr, addr.AddrType)
	}

	// Create a table for port information
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Port", "Protocol", "State", "Service", "Product", "Version"})
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgBlackColor},
	)

	// Populate table with port information
	for _, port := range host.Ports.Port {
		var stateColor tablewriter.Colors
		if port.State.State == "open" {
			stateColor = tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor}
		} else {
			stateColor = tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}
		}

		table.Rich([]string{
			port.PortID,
			port.Protocol,
			port.State.State,
			port.Service.Name,
			port.Service.Product,
			port.Service.Version,
		}, []tablewriter.Colors{
			{},
			{},
			stateColor,
			{},
			{},
			{},
		})
	}
	table.Render()

	// OS Detection
	if len(host.OS.OSMatch) > 0 {
		color.Cyan("\n🖧 Potential OS Detection:")
		for _, osMatch := range host.OS.OSMatch {
			color.Yellow("  • %s (Accuracy: %.2f%%)\n", osMatch.Name, osMatch.Accuracy)
		}
	}
}