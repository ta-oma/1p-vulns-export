# 1p-vulns-export

This is a very rudimentary program that was designed for the purposes of a challenge during an interview process for a CorpSecEng role. 
Uses NIST's NVD API to find the most recent 1Password related CVEs and prints it in CSV format with CVE ID and CVSS score.

## Usage

```bash
go run nvd.go
```

The program outputs CSV data to stdout with the format:
```
Application Name,CVE ID,CVSS Score
1password,CVE-2022-29868,5.5
scim_bridge,CVE-2021-26905,6.5
...
```

To save to a file:
```bash
go run main.go > vulnerabilities.csv
```

## Running Tests

```bash
go test
```


## Future features

Extend to scan multiple applications by accepting a list of keywords:

```go
applications := []string{"1Password", "Chrome", "Firefox"}
for _, app := range applications {
    // fetch vulnerabilities for each app
}
```

Severity Filtering: Add minimum CVSS score threshold:

```go
goif score < *minScore {
    continue // skip low-severity vulnerabilities
}
```
Support different output formats:

```go
switch *outputFormat {
case "json":
    json.NewEncoder(os.Stdout).Encode(results)
case "csv":
    // current CSV output
}
```

Add date parameters to focus on recent vulns:

```go
url += fmt.Sprintf("&pubStartDate=%s&pubEndDate=%s", startDate, endDate)
```
