package sqli

import (
	"fmt"
	"io"
	"log"
	"net/http"
	netUrl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/KennyZ69/go-aptt/types"
	"golang.org/x/net/html"
)

var (
	commonEndpoints = []string{"login", "signin", "signup", "sign", "home", "user", "admin", "search", "product"}
)

func SqlIn(url string) error {
	var wg sync.WaitGroup

	// wg.Add(1)
	// go func() {
	links := GetLinks(url)
	// fmt.Println("Collected links: ", links)

	links = append(links, url) // appending also the base url because I need to find inputs also on that path

	inputs := GetInputs(links)
	// fmt.Println("Collected inputs: ", inputs)

	// }()

	var reports []types.SqliReport
	var payloads = types.AllSqlPayloads
	var reportChan = make(chan types.SqliReport)

	// go routine to collect report into the reports slice
	go func() {
		for report := range reportChan {
			reports = append(reports, report)
		}
	}()

	for link, inputArr := range inputs {
		wg.Add(1)
		go func(l string, inArr []string) {
			defer wg.Done()
			log.Printf("Testing SQL Injection on link: %s\n", link)
			// Run the sqli tests and which send report into the reports channel
			RunSqliTests(l, inputArr, payloads, reportChan)
		}(link, inputArr)
	}

	wg.Wait()
	close(reportChan)
	fmt.Println("Closing channel for reports...")

	log.Println("Generating reports now...")
	report := generateSqliReport(reports)
	log.Println(report)

	return nil
}

// func RunSqliTests(link string, inputs []string, payloads map[string][]string) (types.SqliReport, error) {
func RunSqliTests(link string, inputs []string, payloads map[string][]string, reportChan chan<- types.SqliReport) {
	var report types.SqliReport
	var client = &http.Client{Timeout: 5 * time.Second}
	for _, input := range inputs {
		for category, payloadSet := range payloads {
			for _, payload := range payloadSet {
				start := time.Now()
				inputField := netUrl.Values{}
				inputField.Set(input, payload)

				statusCode, success := SqliRequest(client, link, inputField)

				report = types.SqliReport{
					Endpoint:     link,
					Success:      success,
					StatusCode:   statusCode,
					Payload:      payload,
					PayloadCat:   category,
					ResponseTime: time.Since(start),
				}

				reportChan <- report

			}

		}
	}

	// return report, nil
}

func SqliRequest(client *http.Client, link string, form netUrl.Values) (int, bool) {
	req, err := http.NewRequest("POST", link, strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("Failed to create request to test on, on %s: %v\n", link, err)
		return 0, false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	log.Println("Running a request on: ", link)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request failed for link: %s: %v: %v\n", link, resp.StatusCode, err)
		return resp.StatusCode, false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("There was an error reading the body of the request: %v\n", err)
		return resp.StatusCode, false
	}
	success := types.CheckForSqliIndicators(string(body), resp.StatusCode)

	return resp.StatusCode, success
}

// TODO: finish this func to generate a proper report of the sql injection simulation
func generateSqliReport(reports []types.SqliReport) string {
	var report string

	return report
}

func GetLinks(url string) []string {
	var wg sync.WaitGroup
	links := make(chan string)
	seen := &sync.Map{}
	collectedLinks := []string{}

	wg.Add(1)
	fmt.Println("Starting to collect the found links:")
	go func() {
		defer wg.Done()
		CrawlForLinks(url, &wg, links, seen)
	}()

	wg.Add(1)
	fmt.Println("BruteForce testing possible usually used paths:")
	go func() {
		defer wg.Done()
		bruteForcePaths(url, links)
	}()

	go func() {
		wg.Wait()
		close(links)
	}()

	fmt.Println("Collecting...")
	for link := range links {
		collectedLinks = append(collectedLinks, link)
	}

	return collectedLinks
}

func GetInputs(links []string) map[string][]string {
	var wg sync.WaitGroup
	inputs := make(chan struct {
		Link  string
		Input string
	})

	inputsMap := make(map[string][]string) // map to hold the inputs fields for each link

	fmt.Println("Starting collecting inputs on found links:")
	for _, link := range links {
		wg.Add(1)
		go func(l string) {
			defer wg.Done()
			inputsFields := CrawlForInputs(l, &wg)

			for _, input := range inputsFields {
				inputs <- struct {
					Link  string
					Input string
				}{l, input}
			}
		}(link)
	}

	go func() {
		wg.Wait()
		close(inputs)
	}()

	fmt.Println("Collecting...")
	for item := range inputs {
		inputsMap[item.Link] = append(inputsMap[item.Link], item.Input)
	}

	return inputsMap
}

// using this func to find the common endpoint whether they exist on given app so they can also be tested
func bruteForcePaths(url string, links chan<- string) {
	for _, endpoint := range commonEndpoints {
		fmt.Printf("Testing the existence of the %s endpoint\n", endpoint)
		fullUrl := fmt.Sprintf("%s/%s", url, endpoint)
		resp, err := http.Get(fullUrl)
		if err != nil {
			fmt.Printf("%s endpoint does not exist on %s\n", endpoint, url)
			continue
		}
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
			fmt.Printf("Found valid path: %s: adding into the array\n", fullUrl)
			links <- fullUrl
		}
		resp.Body.Close()
	}
}

// will crawl looking for 'a' tags in the app and getting possible endpoint / paths to than test on
func CrawlForLinks(url string, wg *sync.WaitGroup, links chan<- string, seen *sync.Map) {

	defer wg.Done()

	// seen := make(map[string]bool) // visited links so I do not add them more than once
	// seen := &sync.Map{} // visited links so I do not add them more than once

	if _, exists := seen.LoadOrStore(url, true); exists {
		return
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Problem getting page from: %s: could not crawl for links: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	parsedUrl, err := netUrl.Parse(url)
	if err != nil {
		fmt.Printf("Error in parsing the url: %v\n", err)
	}
	tokenizer := html.NewTokenizer(resp.Body)
	wg.Add(1)
	for {
		// next token (node)
		tt := tokenizer.Next()

		switch {
		case tt == html.TokenType(html.ErrorNode):
			fmt.Println("ErrorNode found somehow on the app: ", url)
			return
		case tt == html.ErrorToken:
			fmt.Println("Either got an error in going through the app or found the end of the page")
			return // error node => end of the file so should stop iterating

		case tt == html.StartTagToken:
			// fmt.Println("Getting the token when iterating")
			token := tokenizer.Token()
			if token.Data == "a" {
				// fmt.Println("Found the 'a' tag")
				for _, attr := range token.Attr {
					if attr.Key == "href" {

						link := attr.Val
						absoluteLink := strings.TrimPrefix(link, "/")

						fmt.Println("Got the link: ", link)
						if !strings.HasPrefix(link, "http") {
							// link = fmt.Sprintf("%s/%s", url, strings.TrimPrefix(link, "/"))
							absoluteLink = parsedUrl.ResolveReference(&netUrl.URL{Path: link}).String()
						}

						if _, exists := seen.LoadOrStore(absoluteLink, true); !exists {
							wg.Add(1)
							go CrawlForLinks(url, wg, links, seen)
						}
					}
				}
			}
		}
	}
	// return
}

// returns a list of input names for each endpoint
// func CrawlForInputs(url string, inputs chan<- string, wg *sync.WaitGroup) {
func CrawlForInputs(url string, wg *sync.WaitGroup) []string {

	defer wg.Done()
	var inputs []string

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error Getting the url: %s: %v\n", url, err)
		// return
		return inputs
	}
	defer resp.Body.Close()
	tokenizer := html.NewTokenizer(resp.Body)

	// body, err := io.ReadAll(resp.Body)
	// fmt.Println(string(body))

	wg.Add(1)
	for {
		tt := tokenizer.Next()
		switch {
		case tt == html.TokenType(html.ErrorNode):
			fmt.Printf("ErrorNode found on the path: %s\n", url)
			// return
			return inputs
		case tt == html.ErrorToken:
			fmt.Printf("Either got an error while going through the path or found the end: %s\n", url)
			if tokenizer.Err() == io.EOF {
				return inputs
			}
			// return
			continue
			// checking for start token or selfclosing tag so it looks also for things like <input/>
		case tt == html.StartTagToken || tt == html.SelfClosingTagToken:
			// case tt == html.SelfClosingTagToken:
			token := tokenizer.Token()
			fmt.Printf("Token: <%s>\n", token.Data)
			if token.Data == "input" || token.Data == "textarea" {
				fmt.Println("found input or textarea on: ", url)
				for _, attr := range token.Attr {
					fmt.Println("ranging through the attributes: ", attr.Key, attr.Val)
					if attr.Key == "name" && attr.Val != "" {
						fmt.Println("Getting the input of: ", attr.Val)
						// inputs <- attr.Val
						inputs = append(inputs, attr.Val)
					}
				}
			}
		}

	}
	// return
	// return inputs
}
