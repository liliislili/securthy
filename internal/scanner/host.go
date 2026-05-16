package scanner

import (
	"context"
	"sync"
	"time"
)

func ScanHost(
	ctx context.Context,
	ip string,
	startPort, endPort int,
	timeout time.Duration,
	workers int,
) []PortResult {

	ports := make(chan int, workers)
	results := make(chan PortResult, workers)

	var wg sync.WaitGroup
	var out []PortResult

	// Workers
	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for port := range ports {
				open := IsOpen(ip, port, timeout)

				select {
				case results <- PortResult{Port: port, Open: open}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(ports)

		for port := startPort; port <= endPort; port++ {
			select {
			case <-ctx.Done():
				return
			case ports <- port:
			}
		}
	}()

	// Close results when done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for {
		select {
		case r, ok := <-results:
			if !ok {
				return out
			}
			out = append(out, r)

		case <-ctx.Done():
			return out
		}
	}
}
