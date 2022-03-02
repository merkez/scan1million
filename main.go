package main

import (
	"archive/zip"
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
	"path/filepath"
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

func downloadZip(f zipFile) {
	resp, _ := http.Get(f.url)
	defer resp.Body.Close()
	fileName := f.path + f.name
	out, _ := os.Create(fileName)
	defer out.Close()
	io.Copy(out, resp.Body)
}

// taken from: https://stackoverflow.com/questions/20357223/easy-way-to-unzip-file-with-golang
func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		// Check for ZipSlip (Directory traversal)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
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
	top_1_million := "https://statvoo.com/dl/top-1million-sites.csv.zip"

	quiet := flag.Bool("q", true, "don't print the data")
	keyLogFile := flag.String("keylog", "keylog.file", "key log file")
	flag.Parse()
	urls := []string{}
	noQUICSites := noQUICsupport{
		sites: map[string]string{},
	}
	currentTime := time.Now().Format("2006-01-02")
	zFile := zipFile{
		name: fmt.Sprintf("top-1million-sites-%s.csv.zip", currentTime),
		path: "data/",
		url:  top_1_million,
	}
	downloadZip(zFile)
	if err := unzip(zFile.path+zFile.name, zFile.path); err != nil {
		fmt.Printf("Err %v", err)
	}
	// file top-1m.csv will be created and deleted as last step
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
	os.Remove(zFile.path + strings.TrimSuffix(zFile.name, ".zip"))
}
