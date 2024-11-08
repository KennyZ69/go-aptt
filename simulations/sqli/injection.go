package sqli

import (
	"fmt"
	"net/http"
	netUrl "net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

var (
	commonEndpoints = []string{"login", "signin", "signup", "sign", "home", "user", "admin", "search", "product"}
)

func SqlIn(url string) error {
	var wg sync.WaitGroup
	seen := &sync.Map{}         // map to keep track of visited endpoints so I dont scan them twice
	paths := make(chan string)  // channel where found links will be stored using crawling
	inputs := make(chan string) // channel where found inputs will be stored using crawling

	wg.Add(1)

	fmt.Println("Starting CrawlForLinks function:")
	go CrawlForLinks(url, &wg, paths, seen) // crawling to find and store the found links (endpoints) on the app

	go bruteForcePaths(url, paths) // trying to find whether some usually used endpoints exists on there by bruteforcing

	go func() {
		wg.Wait()
		close(paths)
	}()

	for _, path := range <-paths {
		fmt.Println("Found and processed link: ", path)
		wg.Add(1)
		pathString := strconv.QuoteRune(path)
		go CrawlForInputs(pathString, inputs, &wg)
	}

	go func() {
		wg.Wait()
		close(inputs)
	}()

	for _, input := range <-inputs {
		fmt.Println("Found input field: ", strconv.QuoteRune(input))
	}

	fmt.Println("Just completed crawling")

	return nil
}

// func generateReport() string {}

// func getPaths(url string, wg *sync.WaitGroup) []string {
// 	var paths []string
// 	paths = append(paths, bruteForcePaths(url)...)
// 	paths = append(paths, CrawlForLinks(url, wg)...)
// 	return paths
// }

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
	return
}

// returns a list of input names for each endpoint
func CrawlForInputs(url string, inputs chan<- string, wg *sync.WaitGroup) {

	defer wg.Done()

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error Getting the url: %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	tokenizer := html.NewTokenizer(resp.Body)

	for {
		tt := tokenizer.Next()
		switch {
		case tt == html.TokenType(html.ErrorNode):
			fmt.Printf("ErrorNode found on the path: %s\n", url)
			return
		case tt == html.ErrorToken:
			fmt.Printf("Either got an error while going through the path or found the end: %s\n", url)
			return
		case tt == html.StartTagToken:
			token := tokenizer.Token()
			if token.Data == "input" || token.Data == "textarea" {
				for _, attr := range token.Attr {
					if attr.Key == "name" {
						fmt.Println("Getting the input of: ", attr.Val)
						inputs <- attr.Val
					}
				}
			}
		}

	}
	return
}
