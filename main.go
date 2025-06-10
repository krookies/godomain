package main

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/parnurzeal/gorequest"
	"strings"
	"sync"
	"time"
)

var (
	hostname string
	guiMode  bool
)

func init() {
	flag.StringVar(&hostname, "host", "", "Enter target domain")
	flag.BoolVar(&guiMode, "gui", false, "Launch GUI mode")
}

func scan(subdomain chan string, host string) {
	for domain := range subdomain {
		func(domain string) {
			defer wg.Done()
			http_res := fmt.Sprintf("http://%s.%s", domain, host)
			https_res := fmt.Sprintf("https://%s.%s", domain, host)
			http_response, _, errs := request.Head(http_res).Timeout(3*time.Second).Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0").
				TLSClientConfig(&tls.Config{InsecureSkipVerify: true}).End()
			if errs != nil {
				https_response, _, _ := request.Head(https_res).Timeout(3*time.Second).Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0").End()
				if https_response != nil && (https_response.StatusCode == 200 || https_response.StatusCode == 403) {
					color.Yellow("[+] Subdomain: %s is accessible\n", https_res)
				}
			} else {
				if http_response != nil && (http_response.StatusCode == 200 || http_response.StatusCode == 403) {
					color.Yellow("[+] Subdomain: %s is accessible\n", https_res)
				}
			}
		}(domain)
	}
}

//go:embed subdomains-100.txt
var subdomains string
var wg sync.WaitGroup
var request = gorequest.New()

func main() {
	flag.Parse()
	
	// If GUI mode is specified, launch graphical interface
	if guiMode {
		fmt.Println("Launching GUI mode...")
		gui := NewGUI()
		gui.Run()
		return
	}
	
	// Command line mode
	if hostname == "" {
		fmt.Println("Subdomain Scanner v2.0")
		fmt.Println("Usage:")
		fmt.Println("  Command line mode: ./godomain -host example.com")
		fmt.Println("  GUI mode: ./godomain -gui")
		flag.Usage()
		return
	}
	
	fmt.Printf("Starting scan for domain: %s\n", hostname)
	fmt.Println("Using optimized scanning method with wildcard detection...")
	
	// Use new scanner
	scanner := NewScanner(hostname)
	
	// Load subdomain list
	var buf bytes.Buffer
	buf.WriteString(subdomains)
	var subdomainList []string
	for {
		line, err := buf.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil {
			break
		}
		if line != "" {
			subdomainList = append(subdomainList, line)
		}
	}
	
	fmt.Printf("Loaded %d subdomains\n", len(subdomainList))
	
	// Start scan
	go func() {
		for progress := range scanner.Progress {
			fmt.Println(progress)
		}
	}()
	
	scanner.ScanSubdomains(subdomainList, 10)
	
	// Display results
	results := scanner.GetResults()
	fmt.Printf("\nScan completed! Found %d valid subdomains:\n", len(results))
	for _, result := range results {
		if result.Status != "Failed" {
			fmt.Printf("  %s.%s (%s) - %s [%s]\n", 
				result.Subdomain, hostname, result.IP, result.Status, result.Method)
		}
	}
}
