package main

import (
	//Standard deps
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	//Foreign deps
	"github.com/jmoiron/jsonq"
)

type finding_data struct {
	selector        int                    // Index in json array
	id              int                    // ID on defectdojo
	cve             string                 // CVE number
	epss_score      float64                // 5 decimals
	epss_percentile float64                // 5 decimals
	body            map[string]interface{} // Finding body on defectdojo
}

type epss_data struct {
	cve        string
	score      float64
	percentile float64
}

// Used so flags can be passed to functions easier
type flags struct {
	authToken string
	ip        string
	port      int
}

/*
for loop iterates through each finding from source json and fills
findings_list_raw with required data for enrichment.
Required data is:
selector (index in source json)
id (finding id on defectdojo)
cve (cve number for reference)
epss_score and epss_percentile will be filled later
*/
func CreateFindingsRaw(jq *jsonq.JsonQuery) []finding_data {
	findings_count, err := jq.Int("count")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Total findings:", findings_count)

	var current_finding finding_data
	var findings_list_raw []finding_data

	for i := 1; i < findings_count; i++ {
		current_finding.cve, err = jq.String("results", strconv.Itoa(i), "vulnerability_ids", "0", "vulnerability_id")
		if err != nil {
			log.Fatal(err)
		}
		if strings.Contains(current_finding.cve, "GHSA") {
			current_finding.cve, err = jq.String("results", strconv.Itoa(i), "vulnerability_ids", "1", "vulnerability_id")
			if err != nil {
				log.Fatal(err)
			}
		}

		current_finding.id, err = jq.Int("results", strconv.Itoa(i), "id")
		if err != nil {
			log.Fatal(err)
		}

		current_finding.selector = i
		current_finding.body, err = jq.Object("results", strconv.Itoa(i))
		if err != nil {
			log.Fatal(err)
		}

		//fmt.Printf("Selector: %v\tFinding ID: %v\tCVE: %s\n", i, current_finding.id, current_finding.cve)

		findings_list_raw = append(findings_list_raw, current_finding)
	}

	return findings_list_raw
}

/*
Fetch all findings from defectdojo
Returns findinghs in json format, string type
*/
func FetchFindings(flags flags) string {
	url := fmt.Sprintf("http://%v:%v/api/v2/findings/?active=true&limit=99999999", flags.ip, flags.port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Authorization", flags.authToken)

	//Send prepared request
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	findings := string([]byte(body))

	return findings
}

/*
Creates a jsonq.JsonQuery object from findings string
*/
func CreateJsonQuery(findings string) *jsonq.JsonQuery {

	var obj map[string]interface{}
	err := json.Unmarshal([]byte(findings), &obj)
	if err != nil {
		log.Fatal(err)
	}

	dec := json.NewDecoder(strings.NewReader(findings))
	dec.Decode(&obj)
	jq := jsonq.NewQuery(obj)

	return jq
}

// Decompress .gz file
func UnGzip(source, target string) error {
	reader, err := os.Open(source)
	if err != nil {
		return err
	}
	defer reader.Close()

	archive, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer archive.Close()

	target = filepath.Join(target, archive.Name)
	writer, err := os.Create(target)
	if err != nil {
		return err
	}
	defer writer.Close()

	_, err = io.Copy(writer, archive)
	return err
}

/*
Downloads todays EPSS data from https://epss.cyentia.com/epss_scores-current.csv.gz
TODO:
[] Dont fetch again if todays data is already available
*/
func FetchEpssData() {
	epss_raw, err := os.Create("epss_raw.csv.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer epss_raw.Close()

	response, err := http.Get("https://epss.cyentia.com/epss_scores-current.csv.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	_, err = io.Copy(epss_raw, response.Body)

	err = UnGzip("./epss_raw.csv.gz", "./epss_raw.csv")
	if err != nil {
		log.Fatal(err)
	}
}

/*
Loads EPSS data from csv into array
Skips first line of csv (metadata)
*/
func LoadEpssData(path string) []epss_data {
	// Read file
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// File to buffer to string
	var buf bytes.Buffer
	_, err = buf.ReadFrom(f)
	if err != nil {
		log.Fatal(err)
	}
	s := buf.String()

	//Skip first line of text (metadata)
	if i := strings.Index(s, "\n"); i != -1 {
		s = s[i+1:]
	} else {
		log.Fatal("Error: Couldnt skip first line of EPSS data")
	}

	// Read csv and and populate epss array
	r := csv.NewReader(strings.NewReader(s))

	var epss_list []epss_data
	var epss_current epss_data

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		cve_temp := record[0]
		score_temp, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			log.Fatal(err)
		}
		percentile_temp, err := strconv.ParseFloat(record[2], 64)
		if err != nil {
			log.Fatal(err)
		}

		epss_current.cve = cve_temp
		epss_current.score = score_temp
		epss_current.percentile = percentile_temp

		epss_list = append(epss_list, epss_current)
	}

	epss_list = epss_list[2:]

	return epss_list
}

/*
Takes list of findings and epss data as input
Adds epss score and percentile to each finding in input findings array
*/
func EnrichFindingData(epssList *[]epss_data, findingsList *[]finding_data) {
	// Create a map for quick lookup of epss_data by CVE
	epssMap := make(map[string]epss_data)
	for _, epss := range *epssList {
		epssMap[epss.cve] = epss
	}

	// Iterate through findings and update scores based on matching CVE
	for i := range *findingsList {
		finding := &(*findingsList)[i]
		if epss, exists := epssMap[finding.cve]; exists {
			// Update finding with the corresponding scores
			finding.epss_score = epss.score
			finding.epss_percentile = epss.percentile

			finding.body["epss_score"] = fmt.Sprintf("%.5f", finding.epss_score)
			finding.body["epss_percentile"] = fmt.Sprintf("%.5f", finding.epss_percentile)
		}
	}
}

/*
Takes jsonq and enriched findings data as input
Iterates through all findings in query, sends patch request if EPSS data of
finding doesnt match with the one in the enriched findings list
*/
func PatchFindingData(findings_list []finding_data, flags flags) {
	for _, finding := range findings_list {
		url := fmt.Sprintf("http://%v:%v/api/v2/findings/%v", flags.ip, flags.port, finding.id)

		payload := finding.body
		//fmt.Println("Body:", finding.body)
		// Serialize the payload to JSON
		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Fatal(err)
		}

		req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Fatal(err)
		}

		req.Header.Set("Authorization", flags.authToken)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Updating finding failed with status code %d\n", resp.StatusCode)
		} else {
			fmt.Printf("Successfully updated finding with ID: %d\n", finding.id)
			//body, err := io.ReadAll(resp.Body)
			//fmt.Println(string([]byte(body)))
		}
	}
}

func main() {
	var flags flags
	flags.authToken = *flag.String("t", "", "Authorization token")
	flags.ip = *flag.String("u", "localhost", "Url")
	flags.port = *flag.Int("p", 8080, "Port")

	fmt.Println("Starting EPSS enrichment...")

	findings := FetchFindings(flags)
	fmt.Println("Fetched all active findings...")

	jq := CreateJsonQuery(findings)

	findings_list := CreateFindingsRaw(jq)
	fmt.Printf("%v findings loaded...\n", len(findings_list))

	fmt.Println("Fetching EPSS data...")
	FetchEpssData()

	epss_data := LoadEpssData("./epss_raw.csv")
	fmt.Printf("%v EPSS scores loaded...\n", len(epss_data))

	EnrichFindingData(&epss_data, &findings_list)
	fmt.Println("Enriched findings...")

	PatchFindingData(findings_list, flags)
	fmt.Println("Findings patched.")
}
