package visualizer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func saveIPListsByService(ipLists map[string][]string) {
	outputDir := "parsedService"
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}

	for service, ips := range ipLists {
		// Use the service name for the filename
		serviceName := extractServiceName(service)
		filename := filepath.Join(outputDir, fmt.Sprintf("%s.txt", serviceName))
		err := writeIPListToFile(filename, ips)
		if err != nil {
			fmt.Printf("Error writing to file %s: %v\n", filename, err)
		}
	}
}

func writeIPListToFile(filename string, ips []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, ip := range ips {
		_, err := file.WriteString(ip + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func extractServiceName(serviceKey string) string {
	// Split the service key by '@' and take the first part as the service name
	parts := strings.Split(serviceKey, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return "Unknown"
}
