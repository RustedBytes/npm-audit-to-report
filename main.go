// This file is part of the npm-audit-to-report project.
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
	errNoData    = errors.New("no data in the audit file")
	errNoSummary = errors.New("no summary auditLine found")
)

type auditLine struct {
	Type string `json:"type"`
	Data struct {
		Advisory struct {
			Created       time.Time `json:"created"`
			Updated       time.Time `json:"updated"`
			FoundBy       any       `json:"found_by"`
			Deleted       any       `json:"deleted"`
			NpmAdvisoryID any       `json:"npm_advisory_id"`
			ReportedBy    any       `json:"reported_by"`
			Metadata      any       `json:"metadata"`
			Cvss          struct {
				VectorString string  `json:"vectorString"`
				Score        float64 `json:"score"`
			} `json:"cvss"`
			References         string `json:"references"`
			Overview           string `json:"overview"`
			Title              string `json:"title"`
			Access             string `json:"access"`
			Severity           string `json:"severity"`
			ModuleName         string `json:"module_name"`
			VulnerableVersions string `json:"vulnerable_versions"`
			GithubAdvisoryID   string `json:"github_advisory_id"`
			Recommendation     string `json:"recommendation"`
			PatchedVersions    string `json:"patched_versions"`
			URL                string `json:"url"`
			Findings           []struct {
				Version string   `json:"version"`
				Paths   []string `json:"paths"`
			} `json:"findings"`
			Cves []string `json:"cves"`
			Cwe  []string `json:"cwe"`
			ID   int      `json:"id"`
		} `json:"advisory"`
		Resolution struct {
			Path     string `json:"path"`
			ID       int    `json:"id"`
			Dev      bool   `json:"dev"`
			Optional bool   `json:"optional"`
			Bundled  bool   `json:"bundled"`
		} `json:"resolution"`
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
	} `json:"data"`
}

func parseJSON(filename string) ([]auditLine, error) {
	var (
		lines []auditLine
		line  auditLine
	)

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return lines, fmt.Errorf("error opening file: %w", err)
	}

	defer func() {
		if err := file.Close(); err != nil {
			log.Fatal("Error closing file: ", err)
		}
	}()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		jsonData := scanner.Text()

		// Parse the JSON data

		err := json.Unmarshal([]byte(jsonData), &line)
		if err != nil {
			return lines, fmt.Errorf("error unmarshalling JSON: %w", err)
		}

		lines = append(lines, line)
	}

	return lines, nil
}

func generateMarkdown(lines []auditLine) (string, error) {
	var (
		text []string
		line auditLine
	)

	if len(lines) == 0 {
		return "", errNoData
	}

	// Get the summary auditLine
	for _, currentLine := range lines {
		if currentLine.Type == "auditSummary" {
			line = currentLine

			break
		}
	}

	// Check if we have the summary auditLine
	if line.Type == "" {
		return "", errNoSummary
	}

	data := line.Data
	vuls := data.Vulnerabilities

	dateTime := gostradamus.UTCNow()
	now := dateTime.Format("YYYY-MM-DD HH:mm:ss")

	text = append(text, fmt.Sprintf("# Security Audit: %s (UTC)", now))
	text = append(text, "")

	text = append(text, "## Dependencies")
	text = append(text, "")
	text = append(text, fmt.Sprintf("- Project: %d", data.Dependencies))
	text = append(text, fmt.Sprintf("- Dev: %d", data.DevDependencies))
	text = append(text, fmt.Sprintf("- Optional: %d", data.OptionalDependencies))
	text = append(text, fmt.Sprintf("- Total: %d", data.TotalDependencies))
	text = append(text, "")

	text = append(text, "## Vulnerabilities")
	text = append(text, "")
	text = append(text, fmt.Sprintf("- 🔵 Info: %d", vuls.Info))
	text = append(text, fmt.Sprintf("- 🟢 Low: %d", vuls.Low))
	text = append(text, fmt.Sprintf("- 🟡 Moderate: %d", vuls.Moderate))
	text = append(text, fmt.Sprintf("- 🟠 High: %d", vuls.High))
	text = append(text, fmt.Sprintf("- 🔴 Critical: %d", vuls.Critical))
	text = append(text, "")

	if len(lines) > 1 {
		text = append(text, "## Advisories")
		text = append(text, "")

		for _, line := range lines {
			advisory := line.Data.Advisory
			if line.Type == "auditAdvisory" {
				text = append(text, fmt.Sprintf("### `%s`: %s", advisory.Severity, advisory.Title))
				text = append(text, "")
				text = append(text, "- URL: "+advisory.URL)
				text = append(text, "")
			}
		}
	}

	return strings.Join(text, "\n"), nil
}

func main() {
	var (
		auditFile               = "security-audit.json"
		outputFile              = "security-audit.md"
		failIfNoVulnerabilities = false
	)

	flaggy.String(&auditFile, "i", "audit-file", "Path to the audit file")
	flaggy.String(&outputFile, "o", "output-file", "Path to the output file")
	flaggy.Bool(&failIfNoVulnerabilities, "f", "fail-if-no-vulnerabilities", "Fail if no vulnerabilities found")
	flaggy.Parse()

	// Check arguments
	if auditFile == "" {
		log.Fatal("Audit file is required")

		return
	}

	// Check existence of the audit file
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		log.Fatal("Audit file not found")

		return
	}

	// Convert JSON to struct
	lines, err := parseJSON(auditFile)
	if err != nil {
		log.Fatal("Error parsing JSON: ", err)
	}

	var totalVulnerabilities int

	// Count the number of vulnerabilities
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
	log.Println(markdown)

	// Write the markdown to the output file
	err = os.WriteFile(outputFile, []byte(markdown), 0o600)
	if err != nil {
		log.Fatal("Error writing to the output file: ", err)
	}
}
