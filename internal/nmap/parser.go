// internal/nmap/parser.go
package nmap

import (
	"encoding/xml"
	"fmt"
	"os"
)

type ScanResult struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Addresses []Address `xml:"address"`
	Ports []Port `xml:"ports>port"`
	OS        OS        `xml:"os"`
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

// Address contains network address information
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   uint16  `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

type State struct {
	State string `xml:"state,attr"`
}

type Service struct {
	Name string `xml:"name,attr"`
	Product string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
}

func Parse(filePath string) (*ScanResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("file open error: %w", err)
	}
	defer file.Close()

	var result ScanResult
	if err := xml.NewDecoder(file).Decode(&result); err != nil {
		return nil, fmt.Errorf("xml decoding error: %w", err)
	}

	return &result, nil
}
