package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bykof/gostradamus"
	"github.com/integrii/flaggy"
)

var (
	auditFile               = "security-audit.json"
	outputFile              = "security-audit.md"
	failIfNoVulnerabilities = false
)

type auditLine struct {
	Type string `json:"type"`
	Data struct {
		Vulnerabilities struct {
			Info     int `json:"info"`
			Low      int `json:"low"`
			Moderate int `json:"moderate"`
			High     int `json:"high"`
			Critical int `json:"critical"`
		} `json:"vulnerabilities"`
		Dependencies         int `json:"dependencies"`
		DevDependencies      int `json:"devDependencies"`
		OptionalDependencies int `json:"optionalDependencies"`
		TotalDependencies    int `json:"totalDependencies"`
		Resolution           struct {
			ID       int    `json:"id"`
			Path     string `json:"path"`
			Dev      bool   `json:"dev"`
			Optional bool   `json:"optional"`
			Bundled  bool   `json:"bundled"`
		} `json:"resolution"`
		Advisory struct {
			Findings []struct {
				Version string   `json:"version"`
				Paths   []string `json:"paths"`
			} `json:"findings"`
			FoundBy            interface{} `json:"found_by"`
			Deleted            interface{} `json:"deleted"`
			References         string      `json:"references"`
			Created            time.Time   `json:"created"`
			ID                 int         `json:"id"`
			NpmAdvisoryID      interface{} `json:"npm_advisory_id"`
			Overview           string      `json:"overview"`
			ReportedBy         interface{} `json:"reported_by"`
			Title              string      `json:"title"`
			Metadata           interface{} `json:"metadata"`
			Cves               []string    `json:"cves"`
			Access             string      `json:"access"`
			Severity           string      `json:"severity"`
			ModuleName         string      `json:"module_name"`
			VulnerableVersions string      `json:"vulnerable_versions"`
			GithubAdvisoryID   string      `json:"github_advisory_id"`
			Recommendation     string      `json:"recommendation"`
			PatchedVersions    string      `json:"patched_versions"`
			Updated            time.Time   `json:"updated"`
			Cvss               struct {
				Score        float64 `json:"score"`
				VectorString string  `json:"vectorString"`
			} `json:"cvss"`
			Cwe []string `json:"cwe"`
			URL string   `json:"url"`
		} `json:"advisory"`
	} `json:"data"`
}

func parseJSON(filename string) ([]auditLine, error) {
	var lines []auditLine

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return lines, err
	}
	defer file.Close()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		jsonData := scanner.Text()

		// Parse the JSON data
		var line auditLine
		err := json.Unmarshal([]byte(jsonData), &line)
		if err != nil {
			return lines, err
		}

		lines = append(lines, line)
	}

	return lines, nil
}

func generateMarkdown(lines []auditLine) (string, error) {
	var r []string

	if len(lines) == 0 {
		return "", errors.New("no data in the audit file")
	}

	// Get the summary auditLine
	var s auditLine
	for _, line := range lines {
		if line.Type == "auditSummary" {
			s = line
			break
		}
	}

	// Check if we have the summary auditLine
	if s.Type == "" {
		return "", errors.New("no summary auditLine found")
	}

	data := s.Data
	vuls := data.Vulnerabilities

	dateTime := gostradamus.UTCNow()
	now := dateTime.Format("YYYY-MM-DD HH:mm:ss")

	r = append(r, fmt.Sprintf("# Security Audit: %s (UTC)", now))
	r = append(r, "")

	r = append(r, "## Dependencies")
	r = append(r, "")
	r = append(r, fmt.Sprintf("- Project: %d", data.Dependencies))
	r = append(r, fmt.Sprintf("- Dev: %d", data.DevDependencies))
	r = append(r, fmt.Sprintf("- Optional: %d", data.OptionalDependencies))
	r = append(r, fmt.Sprintf("- Total: %d", data.TotalDependencies))
	r = append(r, "")

	r = append(r, "## Vulnerabilities")
	r = append(r, "")
	r = append(r, fmt.Sprintf("- 🔵 Info: %d", vuls.Info))
	r = append(r, fmt.Sprintf("- 🟢 Low: %d", vuls.Low))
	r = append(r, fmt.Sprintf("- 🟡 Moderate: %d", vuls.Moderate))
	r = append(r, fmt.Sprintf("- 🟠 High: %d", vuls.High))
	r = append(r, fmt.Sprintf("- 🔴 Critical: %d", vuls.Critical))
	r = append(r, "")

	if len(lines) > 1 {
		r = append(r, "## Advisories")
		r = append(r, "")

		for _, line := range lines {
			advisory := line.Data.Advisory
			if line.Type == "auditAdvisory" {
				r = append(r, fmt.Sprintf("### `%s`: %s", advisory.Severity, advisory.Title))
				r = append(r, "")
				r = append(r, "- URL: "+advisory.URL)
				r = append(r, "")
			}
		}
	}

	return strings.Join(r, "\n"), nil
}

func main() {
	flaggy.String(&auditFile, "i", "audit-file", "Path to the audit file")
	flaggy.String(&outputFile, "o", "output-file", "Path to the output file")
	flaggy.Bool(&failIfNoVulnerabilities, "f", "fail-if-no-vulnerabilities", "Fail if no vulnerabilities found")
	flaggy.Parse()

	// Check existence of the audit file
	if auditFile == "" {
		log.Fatal("Audit file is required")
		return
	}
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		log.Fatal("Audit file not found")
		return
	}

	// Convert JSON to struct
	lines, err := parseJSON(auditFile)
	if err != nil {
		log.Fatal("Error parsing JSON: ", err)
	}

	// Count the number of vulnerabilities
	var totalVulnerabilities int
	for _, line := range lines {
		if line.Type == "auditSummary" {
			totalVulnerabilities += line.Data.Vulnerabilities.Info
			totalVulnerabilities += line.Data.Vulnerabilities.Low
			totalVulnerabilities += line.Data.Vulnerabilities.Moderate
			totalVulnerabilities += line.Data.Vulnerabilities.High
			totalVulnerabilities += line.Data.Vulnerabilities.Critical
		}
	}
	if totalVulnerabilities == 0 && failIfNoVulnerabilities {
		log.Fatal("No vulnerabilities found")
	}

	// Generate the markdown
	markdown, err := generateMarkdown(lines)
	if err != nil {
		log.Fatal("Error generating markdown: ", err)
	}

	// Print the audit content
	fmt.Println(markdown)

	// Write the markdown to the output file
	err = os.WriteFile(outputFile, []byte(markdown), 0644)
	if err != nil {
		log.Fatal("Error writing to the output file: ", err)
	}
}
