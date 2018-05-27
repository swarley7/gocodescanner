package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"./libgocodescanner"
)

func main() {
	cwd, _ := os.Getwd()
	var searchDir, extensions, outputDirectory, reportFilename string
	libgocodescanner.InitLogger(os.Stdout, os.Stdout, os.Stdout, os.Stdout, os.Stderr)

	flag.StringVar(&searchDir, "s", cwd, "Path to analyse")
	flag.StringVar(&extensions, "e", "php,inc", "File extensions to check for vulns")
	flag.StringVar(&outputDirectory, "o", cwd, "Directory to store output files")
	flag.StringVar(&reportFilename, "r", "gocodescanner", "Report filename prefix")

	flag.Parse()

	FileExtensions := strings.Split(extensions, ",")
	fileChan := make(chan string, 1000)
	go func() {
		defer close(fileChan)
		filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
			if !f.IsDir() {
				for _, extension := range FileExtensions {
					if strings.ToLower(filepath.Ext(path)) == strings.ToLower(fmt.Sprintf(".%s", extension)) {
						// fmt.Println(path)
						fileChan <- path
					}
				}
			}
			// close(fileChan)
			return nil
		})
	}()
	ch := make(chan []libgocodescanner.DiscoveredVuln)
	wg := sync.WaitGroup{}

	wg.Add(1)
	go libgocodescanner.OutputResults(&wg, ch, outputDirectory, reportFilename)
	wg.Add(1)
	sub := sync.WaitGroup{}
	go func() {
		defer wg.Done()
		defer close(ch)
		for fname := range fileChan {
			contents, err := ioutil.ReadFile(fname)
			if err != nil {
				panic(err)
			}
			src := libgocodescanner.SourceObj{
				Filename:     fname,
				FileContents: contents,
			}
			sub.Add(1)
			go src.Scanner(&sub, ch)
		}
		sub.Wait()
	}()
	wg.Wait()
	return
}
