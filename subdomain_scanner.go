package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// SubdomainResult subdomain scan result
type SubdomainResult struct {
	Subdomain string
	IP        string
	Status    string
	Method    string
	Error     error
}

// Scanner subdomain scanner
type Scanner struct {
	TargetDomain string
	Results      []SubdomainResult
	mu           sync.Mutex
	Progress     chan string
}

// NewScanner creates a new scanner
func NewScanner(targetDomain string) *Scanner {
	return &Scanner{
		TargetDomain: targetDomain,
		Results:      make([]SubdomainResult, 0),
		Progress:     make(chan string, 100),
	}
}

// CheckWildcardDNS checks for wildcard DNS
func (s *Scanner) CheckWildcardDNS() (bool, []string) {
	randomSubdomains := []string{
		"random" + fmt.Sprintf("%d", time.Now().Unix()),
		"test" + fmt.Sprintf("%d", time.Now().Unix()),
		"invalid" + fmt.Sprintf("%d", time.Now().Unix()),
	}
	
	var wildcardIPs []string
	for _, subdomain := range randomSubdomains {
		fullDomain := subdomain + "." + s.TargetDomain
		ips, err := net.LookupHost(fullDomain)
		if err == nil && len(ips) > 0 {
			wildcardIPs = append(wildcardIPs, ips...)
		}
	}
	
	return len(wildcardIPs) > 0, wildcardIPs
}

// ValidateSubdomain validates a subdomain
func (s *Scanner) ValidateSubdomain(subdomain string) SubdomainResult {
	fullDomain := subdomain + "." + s.TargetDomain
	result := SubdomainResult{
		Subdomain: subdomain,
		Status:    "Not validated",
	}

	// Method 1: DNS resolution
	if ips, err := net.LookupHost(fullDomain); err == nil && len(ips) > 0 {
		result.IP = ips[0]
		result.Status = "DNS resolved"
		result.Method = "DNS"
	} else {
		// Method 2: HTTP request
		if s.checkHTTP(fullDomain) {
			result.Status = "HTTP accessible"
			result.Method = "HTTP"
		} else {
			// Method 3: HTTPS request
			if s.checkHTTPS(fullDomain) {
				result.Status = "HTTPS accessible"
				result.Method = "HTTPS"
			} else {
				result.Status = "Failed"
				result.Error = err
			}
		}
	}

	return result
}

// checkHTTP checks HTTP access
func (s *Scanner) checkHTTP(domain string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	req, err := http.NewRequest("HEAD", "http://"+domain, nil)
	if err != nil {
		return false
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301 || resp.StatusCode == 302
}

// checkHTTPS checks HTTPS access
func (s *Scanner) checkHTTPS(domain string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	req, err := http.NewRequest("HEAD", "https://"+domain, nil)
	if err != nil {
		return false
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301 || resp.StatusCode == 302
}

// ScanSubdomains scans a list of subdomains
func (s *Scanner) ScanSubdomains(subdomains []string, maxWorkers int) {
	// First check for wildcard DNS
	s.Progress <- "Checking for wildcard DNS..."
	hasWildcard, wildcardIPs := s.CheckWildcardDNS()
	if hasWildcard {
		s.Progress <- fmt.Sprintf("Wildcard DNS detected, IPs: %v", wildcardIPs)
	} else {
		s.Progress <- "No wildcard DNS detected"
	}

	// Create work pool
	subdomainChan := make(chan string, len(subdomains))
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range subdomainChan {
				result := s.ValidateSubdomain(subdomain)
				
				// If wildcard detected, filter out results with same IP
				if hasWildcard && result.IP != "" {
					isWildcard := false
					for _, wildcardIP := range wildcardIPs {
						if result.IP == wildcardIP {
							isWildcard = true
							break
						}
					}
					if isWildcard {
						continue
					}
				}
				
				s.mu.Lock()
				s.Results = append(s.Results, result)
				s.mu.Unlock()
				
				if result.Status != "Failed" {
					s.Progress <- fmt.Sprintf("Found subdomain: %s.%s (%s) - %s", 
						result.Subdomain, s.TargetDomain, result.IP, result.Status)
				}
			}
		}()
	}

	// Send subdomains to channel
	for _, subdomain := range subdomains {
		subdomainChan <- subdomain
	}
	close(subdomainChan)

	wg.Wait()
	s.Progress <- "Scan completed"
}

// GetResults gets scan results
func (s *Scanner) GetResults() []SubdomainResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Results
} 