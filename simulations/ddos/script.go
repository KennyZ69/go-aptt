package ddos

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
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

func SendReq(wg *sync.WaitGroup, url string) RequestResult {
	defer wg.Done()
	start := time.Now()
	resp, err := http.Get(url)
	elapsed := time.Since(start)

	var result RequestResult

	mu.Lock()
	totalReq++
	totalTime += elapsed

	if err != nil && resp.StatusCode != 200 {
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

func DosAttack(url string, numRequests, concurrency int) {
	log.Println("Starting the DoS attack simulation test on: ", url)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)
	var results []RequestResult

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		semaphore <- struct{}{} // add an empty struct into the semaphore channel or block it if it is full already so wait till it empties

		go func() {
			defer func() { <-semaphore }() // free up a slot on the semaphore channel
			res := SendReq(&wg, url)
			results = append(results, res)
		}()
	}

	wg.Wait() // wait for all request to complete

	generateReport(concurrency, url)
}

func generateReport(concurrency int, url string) {
	avgRespTime := totalTime / time.Duration(successfulReq)
	failRate := float64(failedReq) / float64(totalReq) * 100

	// make the report var for saving into the sim log file
	report := fmt.Sprintf(`
	======== DoS Attack Simulation Report ========
	Total Requests: %d
	Concurrency Level: %d
	Successful Requests: %d
	Failed Requests: %d
	Failure Rate: %.2f%%
	Average Response Time: %v
	==============================================
	
	Ran on %v.
`, totalReq, concurrency, successfulReq, failedReq, failRate, avgRespTime, time.Now().Format(time.ANSIC))

	log.Print(report)

	for code, count := range statusCodes {
		fmt.Printf("Status Code %d: %d responses\n", code, count)
	}

	log.Printf("DoS Attack Simulation ended on %s. You can find the saved report in the 'dos_sim_report.log'. \n", url)

	saveReportToFile(report, "dos_sim_report.log")
}

func saveReportToFile(report, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating the %s file: %v\n", filename, err)
		return
	}
	defer file.Close()

	_, err = fmt.Fprint(file, report)
	if err != nil {
		log.Fatalf("Error writing to the %s file using Fprintf: %v\n", filename, err)
		return
	}
}
