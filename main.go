package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

// Define the structure for querying the OSV API batch
type OSVBatchRequest struct {
	Queries []Query `json:"queries"`
}

type Query struct {
	Package Package `json:"package"` // Package details (PURL)
}

type Package struct {
	PURL string `json:"purl"` // Package URL (PURL)
}

type OSVBatchResponse struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Parse CycloneDX SBOM to extract dependencies
func parseCycloneDX(sbomFilePath string) ([]Query, error) {
	// Open the CycloneDX SBOM file
	file, err := os.Open(sbomFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening SBOM file: %v", err)
	}
	defer file.Close()

	// Decode the CycloneDX SBOM (assuming JSON format)
	var bom cyclonedx.BOM
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&bom); err != nil {
		return nil, fmt.Errorf("error decoding CycloneDX SBOM: %v", err)
	}

	// Build the OSV Batch query format from the SBOM components
	var queries []Query
	for _, component := range *bom.Components {
		purl, _ := buildPURLAndEcosystem(component)
		queries = append(queries, Query{
			Package: Package{
				PURL: purl,
			},
		})
	}

	return queries, nil
}

// Build the PURL and detect the ecosystem based on the component name or attributes
func buildPURLAndEcosystem(component cyclonedx.Component) (string, string) {
	// Detect ecosystem based on the component name or other attributes
	var ecosystem string
	var purl string

	// Check if the component is a Go package
	if strings.Contains(component.Name, "github.com/") {
		ecosystem = "golang"
		purl = fmt.Sprintf("pkg:golang/%s@%s", component.Name, component.Version)

		// Check if it's an npm package
	} else if strings.Contains(component.Name, "npm") {
		ecosystem = "npm"
		purl = fmt.Sprintf("pkg:npm/%s@%s", component.Name, component.Version)

		// Check if it's a Python package
	} else if strings.Contains(component.Name, "python") {
		ecosystem = "pypi"
		purl = fmt.Sprintf("pkg:pypi/%s@%s", component.Name, component.Version)

		// Check if it's a Maven package
	} else if strings.Contains(component.Name, "maven") {
		ecosystem = "maven"
		purl = fmt.Sprintf("pkg:maven/%s@%s", component.Name, component.Version)

		// Check if it's a Rust package
	} else if strings.Contains(component.Name, "rust") {
		ecosystem = "rust"
		purl = fmt.Sprintf("pkg:rust/%s@%s", component.Name, component.Version)

		// Check if it's a Debian package (could also be dpkg/apt)
	} else if strings.Contains(component.Name, "debian") {
		ecosystem = "debian"
		purl = fmt.Sprintf("pkg:debian/%s@%s", component.Name, component.Version)

		// Default fallback ecosystem
	} else {
		ecosystem = "unknown"
		purl = fmt.Sprintf("pkg:unknown/%s@%s", component.Name, component.Version)
	}

	return purl, ecosystem
}

// Scan the project for vulnerabilities using the OSV Batch API
func scanDependencies(queries []Query) (*OSVBatchResponse, error) {
	// OSV API batch query endpoint
	url := "https://api.osv.dev/v1/querybatch"

	// Create the request body
	requestBody := OSVBatchRequest{
		Queries: queries,
	}

	// Marshal the request body into JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshalling request: %v", err)
	}

	// Make the HTTP request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("error making request to OSV API: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error response from OSV API: %s", body)
	}

	// Unmarshal the JSON response
	var result OSVBatchResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %v", err)
	}

	return &result, nil
}

func main() {
	// Path to the CycloneDX SBOM file
	sbomFilePath := "sbom2.json" // Replace with your SBOM file path

	// Parse the CycloneDX SBOM
	queries, err := parseCycloneDX(sbomFilePath)
	if err != nil {
		log.Fatalf("Error parsing CycloneDX SBOM: %v", err)
	}

	// Scan the dependencies for vulnerabilities using the batch API
	result, err := scanDependencies(queries)
	if err != nil {
		log.Fatalf("Error scanning dependencies: %v", err)
	}

	// Print the vulnerabilities found
	if len(result.Vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found.")
	} else {
		fmt.Println("Vulnerabilities found:")
		for _, vuln := range result.Vulnerabilities {
			fmt.Printf("ID: %s\nSeverity: %s\nDescription: %s\n\n", vuln.ID, vuln.Severity, vuln.Description)
		}
	}
}
