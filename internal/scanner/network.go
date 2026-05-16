package scanner

import (
	"context"
	"sync"
	"time"
)

func ScanNetwork(
	ctx context.Context,
	ips []string,
	startPort, endPort int,
	timeout time.Duration,
	workers int,
) []HostResult {

	results := make(chan HostResult, len(ips))
	var wg sync.WaitGroup
	var out []HostResult

	for _, ip := range ips {
		wg.Add(1)

		go func(ip string) {
			defer wg.Done()

			ports := ScanHost(ctx, ip, startPort, endPort, timeout, workers)

			select {
			case results <- HostResult{
				IP:    ip,
				Ports: ports,
			}:
			case <-ctx.Done():
				return
			}
		}(ip)
	}

	// Close after all hosts finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect
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
