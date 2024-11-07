package sqli

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

var (
	commonEndpoints = []string{"login", "signin", "signup", "sign", "home", "user", "admin", "search", "product"}
)

func SqlIn(url string) error {
	foundCommonPaths := bruteForcePaths(url)

	return nil
}

// func generateReport() string {}

// using this func to find the common endpoint whether they exist on given app so they can also be tested
func bruteForcePaths(url string) []string {
	var validPath []string
	for _, endpoint := range commonEndpoints {
		fullUrl := fmt.Sprintf("%s/%s", url, endpoint)
		resp, err := http.Get(fullUrl)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
			fmt.Println("Found valid path: %s: adding into the array", fullUrl)
			validPath = append(validPath, fullUrl)
		}
		resp.Body.Close()
	}
	return validPath
}

// this would get the links from the starting page
// and later in mainCrawl it would recursively crawl also the found endpoints for more possible endpoints
func crawlForLinks(url string) []string {
	var seen map[string]bool // visited links so I do not add them more than once
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Problem getting page from: %s: could crawl for links", url)
		return nil
	}
	defer resp.Body.Close()

	links := []string{}
	tokenizer := html.NewTokenizer(resp.Body)
	for {
		// next token (node)
		tt := tokenizer.Next()

		switch {
		case tt == html.ErrorToken:
			fmt.Println("Either got an error in going through the app or found the end of the page")
			return links // error node => end of the file so should stop iterating

		case tt == html.StartTagToken:
			fmt.Println("Getting the token when iterating")
			token := tokenizer.Token()
			if token.Data == "a" {
				fmt.Println("Found the 'a' tag")
				for _, attr := range token.Attr {
					if attr.Key == "href" {

						link := attr.Val
						fmt.Println("Got the link: ", link)
						if !strings.HasPrefix(link, "http") {
							link = fmt.Sprintf("%s/%s", url, strings.TrimPrefix(link, "/"))
						}

						if !seen[link] && !strings.Contains(link, "#") {
							seen[link] = true
							links = append(links, link)
							// trying recursion (calling the func on itself) to find subpath on the found link
							fmt.Println("Doing recursion to find endpoints on this find")
							links = append(links, crawlForLinks(link)...)
						}
					}
				}
			}
		}
	}
}
