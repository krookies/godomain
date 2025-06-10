package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// GUI application structure
type GUI struct {
	app          fyne.App
	window       fyne.Window
	scanner      *Scanner
	progressText *widget.Label
	resultList   *widget.List
	results      []SubdomainResult
	filtered     []SubdomainResult
	showFailed   bool
	filterButton *widget.Button
}

// NewGUI creates a new GUI application
func NewGUI() *GUI {
	gui := &GUI{
		app:        app.New(),
		results:    make([]SubdomainResult, 0),
		filtered:   make([]SubdomainResult, 0),
		showFailed: false,
	}
	
	gui.app.SetIcon(nil)
	gui.window = gui.app.NewWindow("Subdomain Scanner v2.0")
	gui.window.Resize(fyne.NewSize(1000, 700))
	gui.window.CenterOnScreen()
	
	return gui
}

// Run the GUI application
func (gui *GUI) Run() {
	gui.setupUI()
	gui.window.ShowAndRun()
}

// setupUI sets up the user interface
func (gui *GUI) setupUI() {
	// Title
	title := widget.NewLabel("Subdomain Scanner")
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	// Input area
	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("Enter target domain (e.g. example.com)")
	
	// Thread count selection
	threadLabel := widget.NewLabel("Threads:")
	threadSelect := widget.NewSelect([]string{"5", "10", "20", "50", "100"}, nil)
	threadSelect.SetSelected("10")
	
	// Dictionary selection
	dictLabel := widget.NewLabel("Subdomain Dictionary:")
	dictSelect := widget.NewSelect([]string{"Built-in (100)", "Custom File"}, nil)
	dictSelect.SetSelected("Built-in (100)")
	
	// Custom dictionary file selection
	dictFileEntry := widget.NewEntry()
	dictFileEntry.SetPlaceHolder("Custom dictionary file path")
	dictFileEntry.Hide()
	
	dictSelect.OnChanged = func(selection string) {
		if selection == "Custom File" {
			dictFileEntry.Show()
		} else {
			dictFileEntry.Hide()
		}
	}
	
	// Start scan button
	startButton := widget.NewButton("Start Scan", func() {
		gui.startScan(domainEntry.Text, threadSelect.Selected, dictSelect.Selected, dictFileEntry.Text)
	})
	startButton.Importance = widget.HighImportance
	
	// Stop scan button
	stopButton := widget.NewButton("Stop Scan", func() {
		gui.stopScan()
	})
	stopButton.Importance = widget.MediumImportance
	
	// Clear results button
	clearButton := widget.NewButton("Clear Results", func() {
		gui.clearResults()
	})
	
	// Filter button
	filterButton := widget.NewButton("Show All", func() {
		gui.toggleFilter()
	})
	gui.filterButton = filterButton
	
	// Export results button
	exportButton := widget.NewButton("Export Results", func() {
		gui.exportResults()
	})
	
	// Progress display
	gui.progressText = widget.NewLabel("Ready")
	gui.progressText.Wrapping = fyne.TextWrapWord
	
	// Results list with click functionality
	gui.resultList = widget.NewList(
		func() int { 
			if gui.showFailed {
				return len(gui.results)
			}
			return len(gui.filtered)
		},
		func() fyne.CanvasObject {
			return container.NewBorder(
				nil, nil, nil, nil,
				container.NewGridWithColumns(4,
					widget.NewLabel("Subdomain"),
					widget.NewLabel("IP Address"),
					widget.NewLabel("Status"),
					widget.NewLabel("Method"),
				),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			var result SubdomainResult
			if gui.showFailed {
				if id < len(gui.results) {
					result = gui.results[id]
				}
			} else {
				if id < len(gui.filtered) {
					result = gui.filtered[id]
				}
			}
			
			if result.Subdomain != "" {
				container := obj.(*fyne.Container)
				grid := container.Objects[0].(*fyne.Container)
				
				// Update list item content with better spacing
				subdomainLabel := grid.Objects[0].(*widget.Label)
				ipLabel := grid.Objects[1].(*widget.Label)
				statusLabel := grid.Objects[2].(*widget.Label)
				methodLabel := grid.Objects[3].(*widget.Label)
				
				fullDomain := result.Subdomain + "." + gui.scanner.TargetDomain
				subdomainLabel.SetText(fullDomain)
				ipLabel.SetText(result.IP)
				statusLabel.SetText(result.Status)
				methodLabel.SetText(result.Method)
				
				// Set minimum width for better readability
				subdomainLabel.Wrapping = fyne.TextTruncate
				ipLabel.Wrapping = fyne.TextTruncate
				statusLabel.Wrapping = fyne.TextTruncate
				methodLabel.Wrapping = fyne.TextTruncate
				
				if result.Status != "Failed" {
					statusLabel.TextStyle = fyne.TextStyle{Bold: true}
				}
			}
		},
	)
	
	// Add click handler for opening browser
	gui.resultList.OnSelected = func(id widget.ListItemID) {
		var result SubdomainResult
		if gui.showFailed {
			if id < len(gui.results) {
				result = gui.results[id]
			}
		} else {
			if id < len(gui.filtered) {
				result = gui.filtered[id]
			}
		}
		
		if result.Subdomain != "" && result.Status != "Failed" {
			fullDomain := result.Subdomain + "." + gui.scanner.TargetDomain
			gui.openInBrowser(fullDomain)
		}
	}
	
	// Layout
	inputForm := container.NewGridWithColumns(2,
		widget.NewLabel("Target Domain:"), domainEntry,
		threadLabel, threadSelect,
		dictLabel, dictSelect,
		widget.NewLabel(""), dictFileEntry,
	)
	
	buttonRow := container.NewHBox(
		startButton, stopButton, clearButton, filterButton, exportButton,
	)
	
	// Create a scrollable results area
	resultsScroll := container.NewScroll(gui.resultList)
	resultsScroll.SetMinSize(fyne.NewSize(900, 400))
	
	// Main content with better proportions
	topSection := container.NewVBox(
		title,
		widget.NewSeparator(),
		inputForm,
		buttonRow,
		widget.NewSeparator(),
		gui.progressText,
	)
	
	bottomSection := container.NewVBox(
		widget.NewLabel("Scan Results:"),
		resultsScroll,
	)
	
	content := container.NewBorder(
		topSection, nil, nil, nil,
		bottomSection,
	)
	
	gui.window.SetContent(content)
}

// startScan starts the scan
func (gui *GUI) startScan(domain, threads, dictType, dictFile string) {
	if domain == "" {
		dialog.ShowError(fmt.Errorf("Please enter a target domain"), gui.window)
		return
	}
	
	threadCount, err := strconv.Atoi(threads)
	if err != nil {
		threadCount = 10
	}
	
	gui.scanner = NewScanner(domain)
	
	var subdomains []string
	if dictType == "Custom File" {
		if dictFile == "" {
			dialog.ShowError(fmt.Errorf("Please select a dictionary file"), gui.window)
			return
		}
		subdomains = gui.loadCustomDict(dictFile)
	} else {
		subdomains = gui.loadBuiltinDict()
	}
	
	if len(subdomains) == 0 {
		dialog.ShowError(fmt.Errorf("Failed to load subdomain dictionary"), gui.window)
		return
	}
	
	gui.progressText.SetText(fmt.Sprintf("Scanning %s, %d subdomains, %d threads", domain, len(subdomains), threadCount))
	
	go func() {
		go func() {
			for progress := range gui.scanner.Progress {
				gui.progressText.SetText(progress)
				gui.updateResults()
			}
		}()
		
		gui.scanner.ScanSubdomains(subdomains, threadCount)
	}()
}

// stopScan stops the scan
func (gui *GUI) stopScan() {
	if gui.scanner != nil {
		gui.progressText.SetText("Scan stopped")
	}
}

// clearResults clears the results
func (gui *GUI) clearResults() {
	gui.results = make([]SubdomainResult, 0)
	gui.filtered = make([]SubdomainResult, 0)
	gui.showFailed = false
	if gui.filterButton != nil {
		gui.filterButton.SetText("Show All")
	}
	gui.resultList.Refresh()
	gui.progressText.SetText("Results cleared")
}

// updateResults updates the result display
func (gui *GUI) updateResults() {
	if gui.scanner != nil {
		gui.results = gui.scanner.GetResults()
		
		// Apply filter to get successful results only
		gui.filtered = make([]SubdomainResult, 0)
		for _, result := range gui.results {
			if result.Status != "Failed" {
				gui.filtered = append(gui.filtered, result)
			}
		}
		
		gui.resultList.Refresh()
	}
}

// exportResults exports the results
func (gui *GUI) exportResults() {
	if len(gui.results) == 0 {
		dialog.ShowError(fmt.Errorf("No results to export"), gui.window)
		return
	}
	
	filename := fmt.Sprintf("subdomain_results_%s_%s.txt", 
		gui.scanner.TargetDomain, 
		time.Now().Format("20060102_150405"))
	
	file, err := os.Create(filename)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to create file: %v", err), gui.window)
		return
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	writer.WriteString(fmt.Sprintf("Subdomain Scan Results - %s\n", gui.scanner.TargetDomain))
	writer.WriteString(fmt.Sprintf("Scan Time: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(strings.Repeat("=", 50) + "\n")
	writer.WriteString("Subdomain\tIP Address\tStatus\tMethod\n")
	
	for _, result := range gui.results {
		if result.Status != "Failed" {
			writer.WriteString(fmt.Sprintf("%s.%s\t%s\t%s\t%s\n",
				result.Subdomain, gui.scanner.TargetDomain,
				result.IP, result.Status, result.Method))
		}
	}
	
	writer.Flush()
	dialog.ShowInformation("Exported", fmt.Sprintf("Results exported to: %s", filename), gui.window)
}

// loadBuiltinDict loads the built-in dictionary
func (gui *GUI) loadBuiltinDict() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
		"cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
		"dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql",
		"old", "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql",
		"secure", "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img",
		"www1", "intranet", "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1",
		"ns4", "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
		"svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2",
		"lyncdiscover", "info", "apps", "download", "remote", "db", "forums", "store",
		"relay", "files", "newsletter", "app", "live", "owa", "en", "start", "sms",
		"office", "exchange", "ipv4",
	}
}

// loadCustomDict loads a custom dictionary
func (gui *GUI) loadCustomDict(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()
	
	var subdomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}
	
	return subdomains
}

// openInBrowser opens the result in the default browser
func (gui *GUI) openInBrowser(url string) {
	// Try to open in default browser
	cmd := exec.Command("open", "http://"+url)
	err := cmd.Start()
	if err != nil {
		// Fallback for different OS
		cmd = exec.Command("xdg-open", "http://"+url)
		err = cmd.Start()
		if err != nil {
			cmd = exec.Command("start", "http://"+url)
			cmd.Start()
		}
	}
}

// toggleFilter toggles the filter between showing all results and filtered results
func (gui *GUI) toggleFilter() {
	gui.showFailed = !gui.showFailed
	if gui.showFailed {
		// Show all results including failed ones
		gui.filterButton.SetText("Show Success Only")
	} else {
		// Show only successful results
		gui.filterButton.SetText("Show All")
	}
	gui.resultList.Refresh()
} 