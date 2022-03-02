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
func unzip(src, dst string) error {
	archive, err := zip.OpenReader(filepath.Join(dst, src))
	if err != nil {
		panic(err)
	}
	defer archive.Close()

	for _, f := range archive.File {
		filePath := filepath.Join(dst, strings.TrimPrefix(strings.TrimSuffix(src, ".zip"), "./data/"))
		fmt.Println("unzipping file ", filePath)

		if !strings.HasPrefix(filePath, filepath.Clean(dst)+string(os.PathSeparator)) {
			fmt.Println("invalid file path")
		}
		if f.FileInfo().IsDir() {
			fmt.Println("creating directory...")
			os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			panic(err)
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			panic(err)
		}

		fileInArchive, err := f.Open()
		if err != nil {
			panic(err)
		}

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			panic(err)
		}

		dstFile.Close()
		fileInArchive.Close()
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
		path: "./data/",
		url:  top_1_million,
	}
	downloadZip(zFile)
	if err := unzip(zFile.name, zFile.path); err != nil {
		fmt.Printf("Err %v", err)
	}
	for _, url := range readURLs("./data/" + strings.TrimSuffix(zFile.name, ".zip"))[1:200] {
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
