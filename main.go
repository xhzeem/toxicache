package main

import (
	"fmt"
	"net"
	"net/url"
	"math/rand"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"
	"runtime"
	"bufio"
	"sync"
	"time"
	"flag"
	"os"
)

// THREADS represents the number of goroutines to be spawned for concurrent processing.
var THREADS int 
var REFLECT int = 0
var userAgent string

type headerCheck struct {
	url    string
	header http.Header
	check  string
}

func main() {
	// Initialize a scanner to read input.
	var sc *bufio.Scanner

	// Get information about the standard input.
	stat, _ := os.Stdin.Stat()

	// Define command-line flags.
	var inputFile string
	flag.StringVar(&inputFile, "i", "", "Input File Location")
	
	outputFile := "/tmp/toxicache-" + time.Now().Format("2006-01-02_15-04-05") + ".txt"
	flag.StringVar(&outputFile, "o", outputFile, "Output File Location")
	
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
	flag.StringVar(&userAgent, "ua", userAgent, "User Agent Header")
	
	THREADS = runtime.NumCPU() * 5
	flag.IntVar(&THREADS, "t", THREADS, "Number of Threads")

	flag.Parse()

	printBanner()

	// Initialize the scanner based on the input source.
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		sc = bufio.NewScanner(os.Stdin)
	} else if inputFile != "" {
		InFile, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer InFile.Close()
		sc = bufio.NewScanner(InFile)
	} else {
		fmt.Fprintln(os.Stderr, "No data available on standard input or first argument.")
		os.Exit(1)
	}

	// Open the output file to redirect standard output.
	OutFile, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer OutFile.Close()

	fmt.Printf("▶ Output will be saved to: " + colorize(outputFile+"\n", "80"))

	// Configure the HTTP client to handle redirects appropriately.
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Initialize a channel for initial checks with a buffer size of THREADS.
	headerChecks := make(chan headerCheck, THREADS)

	// Create a pool of goroutines to perform final checks concurrently.
	done := makePool(headerChecks, func(c headerCheck, output chan headerCheck) {
		reflected, err := checkHeaderReflected(c.url, c.header, c.check)
		if err != nil || !reflected {
			return
		}

		REFLECT++

		fmt.Printf("\n"+colorize("Headers reflected: [%v]", "11"), formatHeaders(c.header))
		fmt.Printf("\n"+c.url+"\n")

		if _, err := fmt.Fprintf(OutFile, "Headers reflected: %v @ %s\n", formatHeaders(c.header), c.url); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
		}
	})

	// Define headers to inject and values to check in response
	headersToCheck := []headerCheck{
		{header: http.Header{"X-Forwarded-Host": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Forwarded-For": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Rewrite-Url": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Host": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"User-Agent": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Handle": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"H0st": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Origin": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Transfer-Encoding": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Original-Url": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Original-Host": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Forwarded-Prefix": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Amz-Server-Side-Encryption": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Amz-Website-Redirect-Location": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Trailer": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Fastly-Ssl": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Fastly-Host": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Fastly-Ff": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Fastly-Client-ip": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Content-Type": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Api-Version": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"AcunetiX-Header": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"Accept-Version": []string{"xhzeem.me"}}, check: "xhzeem.me"},
		{header: http.Header{"X-Forwarded-Proto": []string{"13377"}}, check: ":13377"},
		{header: http.Header{"X-Forwarded-Host": []string{"xhzeem.me"}, "X-Forwarded-Scheme": []string{"http"}}, check: "xhzeem.me"},
	}

	for sc.Scan() {
		for _, hc := range headersToCheck {
			hc.url = sc.Text()
			headerChecks <- hc
		}
	}

	close(headerChecks)
	<-done

	fmt.Printf("\n▶ Number of Reflections Found: " + colorize("%v", "80") + "\n", REFLECT)

}

func colorize(text, color string) string {
	return "\033[38;5;" + color + "m" + text + "\033[0m"
}

func printBanner() {
	bannerFormat := `
_____  ___  __     _   ___    __    ___   _     ____ 
 | |  / / \ \ \_/ | | / / %s  / /\  / / %s | |_| | |_  
 |_|  \_\_/ /_/ \ |_| \_\_, /_/--\ \_\_, |_| | |_|__ 

				      @xhzeem | v0.2				
`
	banner := colorize(fmt.Sprintf(bannerFormat, "`","`"), "204")

	// Print to standard error
	fmt.Fprintln(os.Stderr, banner)
}

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	
	// Proxy: http.ProxyURL(&url.URL{
    //     Scheme: "http", 
    //     Host:   "127.0.0.1:8080",
    // }),

	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
}

var httpClient = &http.Client{
	Transport: transport,
}


func checkHeaderReflected(targetURL string, headers http.Header, checkValue string) (bool, error) {

	modifiedURL, err := toxicParam(targetURL)
	if err != nil {
		fmt.Println("Error modifying URL:", err)
		return false, err // Adjusted to return a bool and an error.
	}	

	req, err := http.NewRequest("GET", modifiedURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", userAgent)

	for key, values := range headers {
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check if the response has a cache header in this list
	if !hasCacheHeader(resp) {
		return false, nil // Early return if no cache header is found
	}

	// Check response headers for reflection
	for _, headerValues := range resp.Header {
		for _, headerValue := range headerValues {
			if strings.Contains(headerValue, checkValue) {
			//	fmt.Printf("Reflected in header: %s: %s\n", headerName, headerValue)
				return true, nil
			}
		}
	}

	// Check response body for reflection
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// Check if the specified value is present in the response body
	if strings.Contains(string(body), checkValue) {
		return true, nil
	}

	return false, nil
}

func toxicParam(targetURL string) (string, error) {
	rand.Seed(time.Now().UnixNano())

	// Generate a random number between 0 and 9999
	randomValue := rand.Intn(9999)

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	// Add the random parameter to the URL's query string
	queryParams := parsedURL.Query()
	queryParams.Set("toxicache", fmt.Sprintf("%d", randomValue))
	parsedURL.RawQuery = queryParams.Encode()

	// Use the modified URL for the request
	modifiedURL := parsedURL.String()

	return modifiedURL, nil
}

func hasCacheHeader(resp *http.Response) bool {
    cacheHeaders := []string{
        "x-cache", "cf-cache-status", "x-drupal-cache", "x-varnish-cache", "akamai-cache-status",
        "server-timing", "x-iinfo", "x-nc", "x-hs-cf-cache-status", "x-proxy-cache",
        "x-cache-hits", "x-cache-status", "x-cache-info", "x-rack-cache", "cdn_cache_status",
        "x-akamai-cache", "x-akamai-cache-remote", "x-cache-remote",
    }

    for _, header := range cacheHeaders {
        if _, ok := resp.Header[http.CanonicalHeaderKey(header)]; ok {
            return true
        }
    }
    return false
}

func formatHeaders(headers map[string][]string) string {
	var headerStrings []string
	for name, values := range headers {
		for _, value := range values {
			headerStrings = append(headerStrings, fmt.Sprintf("%s: %s", name, value))
		}
	}
	return strings.Join(headerStrings, ", ")
}

type workerFunc func(headerCheck, chan headerCheck)

func makePool(input chan headerCheck, fn workerFunc) chan headerCheck {
	var wg sync.WaitGroup

	output := make(chan headerCheck)
	for i := 0; i < THREADS; i++ {
		wg.Add(1)
		go func() {
			for c := range input {
				fn(c, output)
			}
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(output)
	}()

	return output
}
