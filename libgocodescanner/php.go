package libgocodescanner

func SetupChecks() (chk []Check) {
	var SQLiCheck = Check{}
	var FileIncludeCheck = Check{}
	var SSRFCheck = Check{}
	var UnsafeSerialization = Check{}
	var FileDisclosure = Check{}
	var CommandInject = Check{}
	// todo these should be read from a file maybe with a JSON interface defining a "Check"
	SQLiCheck.Init(
		"(SELECT|DELETE|FROM|INSERT|WHERE|LIKE|UPDATE|ORDER\\sBY).*(^\\n)\\$_(GET|REQUEST|POST)\\[(['|\"]?\\w+['|\"]?)\\].*$",
		"SQL injection is lame eh",
		"SQL Injection",
		0.9,
	)
	FileIncludeCheck.Init(
		"(require|include)(_once)?\\s?(\\()?\\s?\\$_(GET|REQUEST|POST)\\[(['|\"]?\\w+['|\"]?)\\].*$",
		"File inclusion is v bad",
		"Remote/Local file inclusion",
		1.0,
	)
	SSRFCheck.Init(
		"curl_exec\\s?\\(\\s?\\.*\\$_(GET|REQUEST|POST)\\[(['|\"]?\\w+['|\"]?)\\].*\\).*$",
		"SSRF is v bad",
		"SSRF",
		0.3,
	)
	UnsafeSerialization.Init(
		"(de|un)?serialize\\s?\\(\\s?\\$_(GET|REQUEST|POST)\\[(['|\"]?\\w+['|\"]?)\\].*$",
		"Serialisation can be v bad",
		"Unsafe serialisation",
		0.8,
	)
	CommandInject.Init(
		"shell_]?(^curl_)(exec|eval)\\s?\\(\\s?\\w?\\$_(GET|REQUEST|POST)\\[(['|\"]?\\w+['|\"]?)\\].*$",
		"Command injection is v bad",
		"Command/shell injection",
		1.0,
	)
	FileDisclosure.Init(
		"fopen\\s?\\(\\$_(GET|REQUEST|POST)\\[(['|\"]?\\w+['|\"]?)\\].*$",
		"File disclosure is v bad",
		"Arbitrary file disclosure",
		0.6,
	)

	chk = append(chk, SQLiCheck, FileIncludeCheck, SSRFCheck, UnsafeSerialization, CommandInject, FileDisclosure)
	return
}
