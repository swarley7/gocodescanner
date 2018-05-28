package libgocodescanner

func SetupChecks() (chk []Check) {
	var SQLiCheck = Check{}
	var FileIncludeCheck = Check{}
	var SSRFCheck = Check{}
	var SSRFCheck2 = Check{}
	var SSRFCheck3 = Check{}

	var UnsafeSerialization = Check{}
	var FileDisclosure = Check{}
	var CommandInject = Check{}

	// todo these should be read from a file maybe with a JSON interface defining a "Check"
	SQLiCheck.Init(
		"(SELECT|DELETE|FROM|INSERT|WHERE|LIKE|UPDATE|ORDER\\sBY).*\\$_(GET|REQUEST|POST|COOKIE).*",
		"SQL injection is lame eh",
		"SQL Injection",
		0.9,
	)
	FileIncludeCheck.Init(
		"(require|include)(_once)?\\s?(\\()?\\s?\\$_(GET|REQUEST|POST|COOKIE).*",
		"File inclusion is v bad",
		"Remote/Local file inclusion",
		1.0,
	)
	SSRFCheck.Init(
		"curl_exec\\s?\\(.*\\$_(GET|REQUEST|POST|COOKIE).*",
		"SSRF is v bad",
		"SSRF",
		0.3,
	)
	SSRFCheck2.Init(
		"curl_setopt\\(.*CURLOPT_URL\\s?,\\s?\\$_(GET|REQUEST|POST|COOKIE).*",
		"SSRF is v bad",
		"SSRF",
		0.3,
	)
	SSRFCheck3.Init(
		"curl_init\\(.*\\$_(GET|REQUEST|POST|COOKIE).*",
		"SSRF is v bad",
		"SSRF",
		0.3,
	)
	UnsafeSerialization.Init(
		"(de|un)?serialize\\s?\\(\\s?\\$_(GET|REQUEST|POST|COOKIE).*",
		"Serialisation can be v bad",
		"Unsafe serialisation",
		0.8,
	)
	CommandInject.Init(
		"(^curl_)(assert|passthru|popen|proc_close|proc_open|proc_get_status|proc_nice|exec|eval|proc_terminate|shell_exec|system)\\s?\\(\\s?\\w?\\$_(GET|REQUEST|POST|COOKIE).*",
		"Command injection is v bad",
		"Command/shell injection",
		1.0,
	)
	FileDisclosure.Init(
		"fopen\\s?\\(\\$_(GET|REQUEST|POST|COOKIE).*",
		"File disclosure is v bad",
		"Arbitrary file disclosure",
		0.6,
	)

	chk = append(chk, SQLiCheck, FileIncludeCheck, SSRFCheck, SSRFCheck2, SSRFCheck3, UnsafeSerialization, CommandInject, FileDisclosure)
	return
}
