package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const API_KEY = "986bf8f8-266f-4f76-94f8-1d5a54275591" //I promise I wouldn't do this in production.

func getLatestCVSS(metrics map[string]any) float64 { //helper func just to get the latest CVSS version of the score
	preferred := []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}

	for _, m := range preferred {
		if arr, ok := metrics[m].([]any); ok && len(arr) > 0 {
			if obj, ok := arr[0].(map[string]any); ok {
				if cvssData, ok := obj["cvssData"].(map[string]any); ok {
					if score, ok := cvssData["baseScore"].(float64); ok {
						return score
					}
				}
			}
		}
	}
	return 0
}

func main() {

	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=1Password&resultsPerPage=200"
	//1st 200 results should be enough since the API filters the results by date starting from the most recent.

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("apiKey", API_KEY)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		panic(fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		panic(err)
	}

	vulns := data["vulnerabilities"].([]any)

	fmt.Printf("Application Name,CVE ID,CVSS Score\n")
	for _, v := range vulns {

		vMap := v.(map[string]any)
		cve := vMap["cve"].(map[string]any)
		cveId := cve["id"].(string)
		metrics := cve["metrics"].(map[string]any)
		criteria := ""
		appName := ""
		configs := cve["configurations"].([]any)
		configMap := configs[0].(map[string]any)
		nodes := configMap["nodes"].([]any)

		for _, node := range nodes {
			nodeMap := node.(map[string]any)
			cpeMatches := nodeMap["cpeMatch"].([]any)

			for _, c := range cpeMatches {
				cpe := c.(map[string]any)
				criteria = cpe["criteria"].(string)
				appName = strings.Split(criteria, ":")[4]
			}
		}

		score := getLatestCVSS(metrics)

		fmt.Printf("%s,%s,%.1f\n", appName, cveId, score)

	}

}
