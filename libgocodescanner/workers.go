package libgocodescanner

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"sync"
)

func OutputResults(wg *sync.WaitGroup, discovered chan []DiscoveredVuln, OutputDirectory string, reportFilename string) {
	defer wg.Done()
	var report bytes.Buffer
	var reportFile string
	currTime := GetTimeString()

	reportFile = path.Join(OutputDirectory, fmt.Sprintf("%v-%v_Report.md", reportFilename, currTime))
	file, err := os.Create(reportFile)
	if err != nil {
		panic(err)
	}
	// Header
	report.WriteString(fmt.Sprintf("# gocodescanner report - %v (%v)\n\n", reportFile, currTime))
	file.WriteString(report.String())
	report.Reset()
	for vulns := range discovered {
		// Info.Printf("Um: %v\n", vulns)
		report.WriteString(fmt.Sprintf("# %v\n\n", vulns[0].Filename))
		descriptionPrinted := make(map[string]bool)

		for _, vuln := range vulns {
			Good.Printf("File [%v] contains a [%v] vulnerability: [chars %v:%v]: [%v]\n", vuln.Filename, vuln.PositiveCheck.CheckName, vuln.LoCs[0], vuln.LoCs[1], string(vuln.VulnerableCode))
			if !descriptionPrinted[vuln.PositiveCheck.CheckName] {
				report.WriteString(fmt.Sprintf("## %v\n\n", vuln.PositiveCheck.CheckName))
				report.WriteString(fmt.Sprintf("%v\n\n", vuln.PositiveCheck.Description))
				descriptionPrinted[vuln.PositiveCheck.CheckName] = true
			}
			report.WriteString(fmt.Sprintf("```\n[%v:%v]\t%v\n```\n\n", vuln.LoCs[0], vuln.LoCs[1], string(vuln.VulnerableCode)))

		}
		file.WriteString(report.String())
		report.Reset()

	}

}

func (src *SourceObj) Scanner(wg *sync.WaitGroup, discovered chan []DiscoveredVuln) {
	defer func() {
		wg.Done()
	}()
	chks := SetupChecks()
	vulns := []DiscoveredVuln{}
	for _, check := range chks {
		// fmt.Printf("Testing for %v vulnerabilities in %v\n", check.CheckName, src.Filename)
		results, err := check.RunCheck(src)
		if err != nil {
			continue
		}
		for _, match := range results {
			vuln := DiscoveredVuln{
				Filename:       src.Filename,
				LoCs:           match,
				VulnerableCode: string(src.FileContents[match[0]:match[1]]),
				PositiveCheck:  check,
			}
			vulns = append(vulns, vuln)
		}
	}
	if len(vulns) > 0 {
		discovered <- vulns
	}
}
