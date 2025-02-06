package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"time"
	"regexp"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/pandatix/nvdapi/v2"
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
	table.SetHeader([]string{"Port", "Protocol", "State", "Service", "Product", "Version", "CVEs", "Critical CVE"})
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgBlackColor},
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

		// Fetch CVEs for the service version
		cves, criticalCVE := fetchCVEs(port.Service.Product, port.Service.Version)

		table.Rich([]string{
			port.PortID,
			port.Protocol,
			port.State.State,
			port.Service.Name,
			port.Service.Product,
			port.Service.Version,
			fmt.Sprintf("%d", len(cves)),
			criticalCVE,
		}, []tablewriter.Colors{
			{},
			{},
			stateColor,
			{},
			{},
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

func fetchCVEs(product, version string) ([]string, string) {
	if product == "" || version == "" {
		return nil, ""
	}

	// Retrieve API key from environment variable
	apiKey := os.Getenv("NVD_API_KEY")
	if apiKey == "" {
		log.Println("Warning: NVD API Key not set. Set NVD_API_KEY environment variable.")
		return nil, ""
	}

	// Normalize the version string (strip extra OS metadata)
	normalizedVersion := cleanVersion(version)

	// Create an authenticated NVD API client
	client, err := nvdapi.NewNVDClient(&http.Client{}, apiKey)
	if err != nil {
		log.Printf("Error initializing NVD API client: %v", err)
		return nil, ""
	}

	// Create a keyword for the search
	keyword := fmt.Sprintf("%s %s", product, normalizedVersion)

	// Retry settings
	maxRetries := 3
	delay := 2 * time.Second
	var cves *nvdapi.CVEResponse

	log.Printf("Querying the NVD API for CVE Infos for %s %s (Might be slow)", product, normalizedVersion)
	for attempt := 1; attempt <= maxRetries; attempt++ {
		cves, err = nvdapi.GetCVEs(client, nvdapi.GetCVEsParams{
			KeywordSearch: ptr(keyword),
		})
		if err == nil {
			log.Printf("Query succeded, number of CVEs was %d", cves)
			break // Success, exit retry loop
		}

		//log.Printf("Attempt %d/%d - Error fetching CVEs for %s %s: %v", attempt, maxRetries, product, normalizedVersion, err)

		// If it's a 503 error, apply exponential backoff
		if attempt < maxRetries {
			time.Sleep(delay)
			delay *= 2 // Double the waiting time between requests after each 503
		} else {
			log.Printf("Failed to fetch CVEs for %s %s after %d attempts", product, normalizedVersion, maxRetries)
			return nil, ""
		}
	}

	var cveIDs []string

	// Extract CVE IDs from the response
	for _, vuln := range cves.Vulnerabilities {
		if vuln.CVE.ID != nil {
			cveIDs = append(cveIDs, *vuln.CVE.ID)
		}
	}

	// Sort CVEs by severity (CVSSv3 score)
	sort.Slice(cves.Vulnerabilities, func(i, j int) bool {
		if len(cves.Vulnerabilities[i].CVE.Metrics.CVSSMetricV31) > 0 && len(cves.Vulnerabilities[j].CVE.Metrics.CVSSMetricV31) > 0 {
			return cves.Vulnerabilities[i].CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore >
				cves.Vulnerabilities[j].CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		}
		return false
	})

	// Determine the most critical CVE
	criticalCVE := ""
	if len(cves.Vulnerabilities) > 0 && cves.Vulnerabilities[0].CVE.ID != nil {
		criticalCVE = *cves.Vulnerabilities[0].CVE.ID
	}

	return cveIDs, criticalCVE
}

// Helper function to convert a string to a pointer
func ptr[T any](t T) *T {
	return &t
}

// Normalize version string (strip extra OS metadata)
func cleanVersion(version string) string {
	// Regular expression to extract only version numbers (and suffixes like "p1")
	re := regexp.MustCompile(`\d+(\.\d+)*[a-zA-Z0-9]*`)
	match := re.FindString(version)
	if match != "" {
		return match
	}
	return version // Return original if no match found
}
