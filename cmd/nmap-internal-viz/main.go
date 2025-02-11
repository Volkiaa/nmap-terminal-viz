// cmd/nmap-terminal-viz/main.go
package main

import (
	"fmt"
	"os"

	"github.com/Volkiaa/nmap-terminal-viz/internal/nmap"
	"github.com/Volkiaa/nmap-terminal-viz/internal/visualizer"
	//"github.com/Volkiaa/nmap-terminal-viz/internal/cveCheck"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: nmap-terminal-viz <nmap-xml-file>")
		os.Exit(1)
	}

	result, err := nmap.Parse(os.Args[1])
	if err != nil {
		fmt.Printf("Error parsing NMAP data: %v\n", err)
		os.Exit(1)
	}

	visualizer.Display(result)
}
