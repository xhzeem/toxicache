
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type headerCheck struct {
	target  string
	header  map[string]string
	check   string
	payload string
}

var (
	threads   = defaultThreads()
	reflected uint64
	errors    uint64

	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

	output  *os.File
	writeMu sync.Mutex

	payloads []string

	client = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   50,
			MaxConnsPerHost:       50,
			IdleConnTimeout:       45 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

var headers = []string{
	"X-Forwarded-Host",
	"X-Forwarded-For",
	"X-Rewrite-Url",
	"X-Host",
	"User-Agent",
	"Handle",
	"H0st",
	"Origin",
	"Transfer-Encoding",
	"X-Original-Url",
	"X-Original-Host",
	"X-Forwarded-Prefix",
	"X-Amz-Server-Side-Encryption",
	"X-Amz-Website-Redirect-Location",
	"Trailer",
	"Fastly-Ssl",
	"Fastly-Host",
	"Fastly-Ff",
	"Fastly-Client-ip",
	"Content-Type",
	"Api-Version",
	"AcunetiX-Header",
	"Accept-Version",
}

func defaultThreads() int {
	n := runtime.NumCPU() * 5

	if n < 10 {
		return 10
	}
	if n > 50 {
		return 50
	}

	return n
}

func main() {
	var inputFile, outputPath, payloadInput string

	flag.StringVar(&inputFile, "i", "", "Input file (default: stdin)")
	flag.StringVar(
		&outputPath,
		"o",
		"/tmp/toxicache-"+time.Now().Format("20060102-150405")+".txt",
		"Output file",
	)
	flag.StringVar(&payloadInput, "p", "evil.com", "Comma-separated payloads")
	flag.StringVar(&userAgent, "ua", userAgent, "HTTP User-Agent")
	flag.IntVar(&threads, "t", threads, "Number of workers")
	flag.Parse()

	if threads < 1 || threads > 200 {
		fmt.Fprintln(os.Stderr, "[-] Threads must be between 1 and 200")
		os.Exit(1)
	}

	payloads = parsePayloads(payloadInput)

	if len(payloads) == 0 {
		fmt.Fprintln(os.Stderr, "[-] No valid payloads supplied")
		os.Exit(1)
	}

	printBanner()

	var input io.Reader = os.Stdin

	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Input error: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		input = file
	}

	var err error

	output, err = os.OpenFile(
		outputPath,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Output error: %v\n", err)
		os.Exit(1)
	}
	defer output.Close()

	fmt.Printf("[+] Workers  : %d\n", threads)
	fmt.Printf("[+] Payloads : %s\n", strings.Join(payloads, ", "))
	fmt.Printf("[+] Output   : %s\n\n", outputPath)

	jobs := make(chan headerCheck, threads*4)

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for job := range jobs {
				found, err := checkHeaderReflected(job)

				if err != nil {
					atomic.AddUint64(&errors, 1)
					continue
				}

				if !found {
					continue
				}

				atomic.AddUint64(&reflected, 1)
				writeResult(job)
			}
		}()
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	var targetCount uint64

	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())

		if target == "" || strings.HasPrefix(target, "#") {
			continue
		}

		if err := validateTarget(target); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"[!] Skipping: %s (%v)\n",
				target,
				err,
			)
			continue
		}

		atomic.AddUint64(&targetCount, 1)

		for _, payload := range payloads {
			for _, header := range headers {
				jobs <- headerCheck{
					target: target,
					header: map[string]string{
						header: payload,
					},
					check:   payload,
					payload: payload,
				}
			}

			// Combined header test
			jobs <- headerCheck{
				target: target,
				header: map[string]string{
					"X-Forwarded-Host":   payload,
					"X-Forwarded-Scheme": "http",
				},
				check:   payload,
				payload: payload,
			}
		}

		// Port reflection test
		jobs <- headerCheck{
			target: target,
			header: map[string]string{
				"X-Forwarded-Proto": "13377",
			},
			check:   "13377",
			payload: "13377",
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Input error: %v\n", err)
	}

	close(jobs)
	wg.Wait()

	fmt.Println("\n----------------------------------------")
	fmt.Printf("[+] Targets scanned : %d\n", atomic.LoadUint64(&targetCount))
	fmt.Printf("[+] Reflections     : %d\n", atomic.LoadUint64(&reflected))
	fmt.Printf("[+] Request errors  : %d\n", atomic.LoadUint64(&errors))
	fmt.Printf("[+] Results saved   : %s\n", outputPath)
	fmt.Println("----------------------------------------")
}

func validateTarget(target string) error {
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return fmt.Errorf("invalid URL")
	}

	scheme := strings.ToLower(u.Scheme)

	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("HTTP/HTTPS scheme required")
	}

	if u.Hostname() == "" {
		return fmt.Errorf("missing hostname")
	}

	if u.User != nil {
		return fmt.Errorf("URL credentials are not allowed")
	}

	if strings.ContainsAny(target, "\r\n\t ") {
		return fmt.Errorf("URL contains whitespace or control characters")
	}

	return nil
}

func parsePayloads(input string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, p := range strings.Split(input, ",") {
		p = strings.TrimSpace(p)

		if p == "" || seen[p] {
			continue
		}

		// Prevent HTTP header injection
		if strings.ContainsAny(p, "\r\n") {
			continue
		}

		seen[p] = true
		result = append(result, p)
	}

	return result
}

func checkHeaderReflected(job headerCheck) (bool, error) {
	modifiedURL, err := toxicParam(job.target)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest(
		http.MethodGet,
		modifiedURL,
		nil,
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	for key, value := range job.header {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Inspect response headers
	for _, values := range resp.Header {
		for _, value := range values {
			if strings.Contains(
				strings.ToLower(value),
				strings.ToLower(job.check),
			) {
				_, _ = io.Copy(
					io.Discard,
					io.LimitReader(resp.Body, 64*1024),
				)
				return true, nil
			}
		}
	}

	// Inspect bounded response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return false, err
	}

	return strings.Contains(
		strings.ToLower(string(body)),
		strings.ToLower(job.check),
	), nil
}

func toxicParam(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("HTTP/HTTPS scheme required")
	}

	if u.Hostname() == "" {
		return "", fmt.Errorf("missing hostname")
	}

	random := make([]byte, 8)

	if _, err := rand.Read(random); err != nil {
		return "", err
	}

	query := u.Query()
	query.Set("toxicache", hex.EncodeToString(random))
	u.RawQuery = query.Encode()

	return u.String(), nil
}

func formatHeaders(h map[string]string) string {
	keys := make([]string, 0, len(h))

	for key := range h {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	var result []string

	for _, key := range keys {
		result = append(result, key+": "+h[key])
	}

	return strings.Join(result, ", ")
}

func writeResult(job headerCheck) {
	writeMu.Lock()
	defer writeMu.Unlock()

	const (
		cyan   = "\033[38;5;45m"
		yellow = "\033[38;5;220m"
		green  = "\033[38;5;82m"
		reset  = "\033[0m"
	)

	keys := make([]string, 0, len(job.header))

	for key := range job.header {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	var coloredParts []string
	var plainParts []string

	for _, key := range keys {
		value := job.header[key]

		coloredParts = append(
			coloredParts,
			cyan+key+reset+": "+yellow+value+reset,
		)

		plainParts = append(
			plainParts,
			key+": "+value,
		)
	}

	// Colored terminal output
	fmt.Printf(
		"Headers reflected: [%s]\n%s%s%s\n\n",
		strings.Join(coloredParts, ", "),
		green,
		job.target,
		reset,
	)

	// Plain-text output file
	if _, err := fmt.Fprintf(
		output,
		"Headers reflected: [%s]\n%s\n\n",
		strings.Join(plainParts, ", "),
		job.target,
	); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Write error: %v\n", err)
	}
}

func printBanner() {
	const red, reset = "\033[0;31m", "\033[0m"

	banner := ` _______  _____  _     _ _____ _______ _______ _______ _     _ _______
    |    |     |  \___/    |   |       |_____| |       |_____| |______
    |    |_____| _/   \_ __|__ |_____  |     | |_____  |     | ______`

	fmt.Fprintln(os.Stderr, red+banner+reset)
}
