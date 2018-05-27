package libgocodescanner

import (
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

// type Check struct {

// }
// Get yo colours sorted
var g = color.New(color.FgGreen, color.Bold)
var y = color.New(color.FgYellow, color.Bold)
var r = color.New(color.FgRed, color.Bold)
var m = color.New(color.FgMagenta, color.Bold)
var b = color.New(color.FgBlue, color.Bold)

var (
	Good    *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Debug   *log.Logger
	Error   *log.Logger
)

// var g, y, r, m, b *color.Color
func InitLogger(
	goodHandle io.Writer,
	infoHandle io.Writer,
	debugHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Good = log.New(goodHandle,
		g.Sprintf("GOOD: "),
		log.Ldate|log.Ltime)

	Info = log.New(infoHandle,
		b.Sprintf("INFO: "),
		log.Ldate|log.Ltime)

	Debug = log.New(debugHandle,
		y.Sprintf("DEBUG: "),
		log.Ldate|log.Ltime)

	Warning = log.New(warningHandle,
		m.Sprintf("WARNING: "),
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		r.Sprintf("ERROR: "),
		log.Ldate|log.Ltime|log.Lshortfile)
}

type SourceObj struct {
	Filename     string
	FileContents []byte
	// Regex        *regexp.Regexp
}

type DiscoveredVuln struct {
	VulnType       string
	Filename       string
	LoCs           []int
	VulnerableCode string
	PositiveCheck  Check
}

type Check struct {
	Regex       *regexp.Regexp
	Description string
	CheckName   string
	Severity    float64
}

func (chk *Check) Init(re string, desc string, name string, severity float64) {
	var err error
	chk.Regex, err = regexp.Compile(re)
	if err != nil {
		panic(err)
	}
	chk.Description = desc
	chk.Severity = severity
	chk.CheckName = name
}

func (chk *Check) RunCheck(src *SourceObj) ([][]int, error) {
	matches := chk.Regex.FindAllSubmatchIndex(src.FileContents, -1)
	if len(matches) > 0 {
		return matches, nil
	} else {
		return nil, errors.New("No matches")
	}
}

// LeftPad2Len https://github.com/DaddyOh/golang-samples/blob/master/pad.go
func LeftPad2Len(s string, padStr string, overallLen int) string {
	var padCountInt int
	padCountInt = 1 + ((overallLen - len(padStr)) / len(padStr))
	var retStr = strings.Repeat(padStr, padCountInt) + s
	return retStr[(len(retStr) - overallLen):]
}

// RightPad2Len https://github.com/DaddyOh/golang-samples/blob/master/pad.go
func RightPad2Len(s string, padStr string, overallLen int) string {
	var padCountInt int
	padCountInt = 1 + ((overallLen - len(padStr)) / len(padStr))
	var retStr = s + strings.Repeat(padStr, padCountInt)
	return retStr[:overallLen]
}
func GetTimeString() (currTime string) {
	t := time.Now()
	currTime = fmt.Sprintf("%d%d%d%d%d%d", t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
	return
}
