package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
)

type bufferedWriteCloser struct {
	*bufio.Writer
	io.Closer
}

type noQUICsupport struct {
	m     sync.Mutex
	sites map[string]string
}
type zipFile struct {
	name string
	path string
	url  string
}

// NewBufferedWriteCloser creates an io.WriteCloser from a bufio.Writer and an io.Closer
func NewBufferedWriteCloser(writer *bufio.Writer, closer io.Closer) io.WriteCloser {
	return &bufferedWriteCloser{
		Writer: writer,
		Closer: closer,
	}
}

func (h bufferedWriteCloser) Close() error {
	if err := h.Writer.Flush(); err != nil {
		return err
	}
	return h.Closer.Close()
}

func readURLs(dataPath string) [][]string {
	f, err := os.Open(dataPath)
	if err != nil {
		log.Fatal("Unable to read input file "+dataPath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal("Unable to parse file as CSV for "+dataPath, err)
	}

	return records
}

func main() {

	quiet := flag.Bool("q", true, "don't print the data")
	keyLogFile := flag.String("keylog", "keylog.file", "key log file")
	flag.Parse()
	urls := []string{}
	noQUICSites := noQUICsupport{
		sites: map[string]string{},
	}
	currentTime := time.Now().Format("2006-01-02")

	for _, url := range readURLs("./data/top-1m.csv")[1:] {
		urls = append(urls, fmt.Sprintf("https://www.%s", url[1]))
	}
	fmt.Printf("Number of urls %v\n", len(urls))

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	var qconf quic.Config
	tracer := qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
		filename := fmt.Sprintf("client_%x.qlog", connID)
		f, err := os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Creating qlog file %s.\n", filename)
		return NewBufferedWriteCloser(bufio.NewWriter(f), f)
	})
	if !*quiet {
		qconf.Tracer = tracer
	}
	qconf.Versions = []quic.VersionNumber{quic.Version1}

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: true,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
	}

	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}
	var wg sync.WaitGroup
	wg.Add(len(urls))

	headersFolder := "./headers/" + currentTime

	if err := os.MkdirAll(headersFolder, os.ModePerm); err != nil {
		fmt.Printf("Error on creating directory %v\n", err)
	}
	noQUIC := headersFolder + "/" + "no-quic-implementation-" + currentTime + ".txt"
	noQUICFile, err := os.Create(noQUIC)
	if err != nil {
		log.Fatal(err)
	}
	for _, addr := range urls {
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				noQUICSites.m.Lock()
				_, ok := noQUICSites.sites[addr]
				if !ok {
					noQUICSites.sites[addr] = err.Error()
				}
				noQUICSites.m.Unlock()
				wg.Done()
				return
			}
			headersFileName := headersFolder + "/" + "header-" + strings.Split(addr, "https://www.")[1] + ".txt"
			f, err := os.Create(headersFileName)
			if err != nil {
				log.Fatal(err)
			}
			for k, v := range rsp.Header {
				f.WriteString(fmt.Sprintf("%v : %v \n", k, v))
			}
			defer f.Close()
			defer wg.Done()
		}(addr)
	}
	wg.Wait()
	for k, v := range noQUICSites.sites {
		noQUICFile.WriteString(fmt.Sprintf("%s , %s \n", k, v))
	}
	noQUICFile.Close()
}
