package cvechecker

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"regexp"
	"time"

	nvdapi "github.com/pandatix/nvdapi/v2"
)


// FetchCVEs retrieves CVEs for a given product and version using the NVD API.
func FetchCVEs(product, version string) ([]string, string) {
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
	delay := time.Second
	var cves *nvdapi.CVEResponse

	log.Printf("Querying the NVD API for CVE Infos for %s %s (Might be slow)", product, normalizedVersion)
	for attempt := 1; attempt <= maxRetries; attempt++ {
		cves, err = nvdapi.GetCVEs(client, nvdapi.GetCVEsParams{
			KeywordSearch: ptr(keyword),
		})
		if err == nil {
			//log.Printf("Query succeeded, number of CVEs was %d", len(cves.Vulnerabilities))
			break // Success, exit retry loop
		}

		if attempt < maxRetries {
			time.Sleep(delay)
			delay += 2 // Fast backoff (+=2) Exponential backoff (*=2)
		} else {
			log.Printf("Failed to fetch CVEs for %s %s after %d attempts, NVD API seems down", product, normalizedVersion, maxRetries)
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
