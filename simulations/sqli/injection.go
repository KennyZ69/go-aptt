package sqli

import (
	"fmt"
	"golang.org/x/net/html"
	"net/http"
	netUrl "net/url"
	"strings"
)

var (
	commonEndpoints = []string{"login", "signin", "signup", "sign", "home", "user", "admin", "search", "product"}
)

func SqlIn(url string) error {
	// paths := getPaths(url)

	return nil
}

// func generateReport() string {}
func getPaths(url string) []string {
	var paths []string
	paths = append(paths, bruteForcePaths(url)...)
	paths = append(paths, CrawlForLinks(url)...)
	return paths
}

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
			fmt.Printf("Found valid path: %s: adding into the array\n", fullUrl)
			validPath = append(validPath, fullUrl)
		}
		resp.Body.Close()
	}
	return validPath
}

// will crawl looking for 'a' tags in the app and getting possible endpoint / paths to than test on
func CrawlForLinks(url string) []string {
	seen := make(map[string]bool) // visited links so I do not add them more than once
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Problem getting page from: %s: could crawl for links\n", url)
		return nil
	}
	defer resp.Body.Close()

	links := []string{}
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
			return links
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
						absoluteLink := link

						fmt.Println("Got the link: ", link)
						if !strings.HasPrefix(link, "http") {
							// link = fmt.Sprintf("%s/%s", url, strings.TrimPrefix(link, "/"))
							absoluteLink = parsedUrl.ResolveReference(&netUrl.URL{Path: link}).String()
						}

						if !seen[absoluteLink] && !strings.Contains(link, "#") && link != "/" {
							seen[absoluteLink] = true
							links = append(links, absoluteLink)
							// trying recursion (calling the func on itself) to find subpath on the found link
							fmt.Println("Doing recursion to find endpoints on this find")
							links = append(links, CrawlForLinks(absoluteLink)...)
						}
						return links
					}
				}
			}
		}
	}
	return links
}
