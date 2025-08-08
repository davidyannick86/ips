package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IPResult struct {
	IP        string
	Available bool
	Hostname  string
}

// fastPingIP teste plusieurs ports communs en parallèle.
func fastPingIP(ctx context.Context, ip string) bool {
	ports := []string{"80", "22", "443", "53", "8080", "23", "21", "25"}

	results := make(chan bool, len(ports))
	for _, port := range ports {
		go func(p string) {
			select {
			case <-ctx.Done():
				results <- false
				return
			default:
			}
			d := net.Dialer{Timeout: 100 * time.Millisecond}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, p))
			if err == nil && conn != nil {
				conn.Close()
				results <- true
				return
			}
			results <- false
		}(port)
	}

	for i := 0; i < len(ports); i++ {
		select {
		case <-ctx.Done():
			return false
		case ok := <-results:
			if ok {
				return true
			}
		}
	}
	return false
}

// ScanIPRange scanne 192.168.1.2 -> 192.168.1.245 et ne retourne que les IP libres.
func ScanIPRange(ctx context.Context) []IPResult {
	var results []IPResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	semaphore := make(chan struct{}, 50)

	for i := 2; i <= 245; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if ctx.Err() != nil {
				return
			}
			ip := fmt.Sprintf("192.168.1.%d", i)
			available := fastPingIP(ctx, ip)

			mu.Lock()
			results = append(results, IPResult{
				IP:        ip,
				Available: available,
				Hostname:  "",
			})
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	var filteredResults []IPResult
	for _, result := range results {
		if !result.Available {
			filteredResults = append(filteredResults, result)
		}
	}

	sort.Slice(filteredResults, func(i, j int) bool {
		iParts := strings.Split(filteredResults[i].IP, ".")
		jParts := strings.Split(filteredResults[j].IP, ".")
		if len(iParts) == 4 && len(jParts) == 4 {
			iLast, _ := strconv.Atoi(iParts[3])
			jLast, _ := strconv.Atoi(jParts[3])
			return iLast < jLast
		}
		return filteredResults[i].IP < filteredResults[j].IP
	})

	return filteredResults
}
