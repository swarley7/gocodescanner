package libgocodescanner

import (
	"fmt"
	"strings"
)

// PrintBanner prints the banner... HOW GOOD IS THE BANNER?
func PrintBanner() {
	var banner string
	banner = `                                              $$\
                                              $$ |
 $$$$$$\   $$$$$$\   $$$$$$$\  $$$$$$\   $$$$$$$ | $$$$$$\   $$$$$$$\  $$$$$$$\ $$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\
$$  __$$\ $$  __$$\ $$  _____|$$  __$$\ $$  __$$ |$$  __$$\ $$  _____|$$  _____|\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\
$$ /  $$ |$$ /  $$ |$$ /      $$ /  $$ |$$ /  $$ |$$$$$$$$ |\$$$$$$\  $$ /      $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |  $$ |$$ |      $$ |  $$ |$$ |  $$ |$$   ____| \____$$\ $$ |     $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |
\$$$$$$$ |\$$$$$$  |\$$$$$$$\ \$$$$$$  |\$$$$$$$ |\$$$$$$$\ $$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |
 \____$$ | \______/  \_______| \______/  \_______| \_______|\_______/  \_______|\_______|\__|  \__|\__|  \__| \_______|\__|
$$\   $$ |
\$$$$$$  |
 \______/
`

	var version = "Alpha (0.1a)"
	var author = "Clinton \"swarley\" Carpene (@swarley777)"

	// g := color.New(color.FgGreen, color.Bold)

	fmt.Printf("%v\n", strings.Replace(banner, "$", g.Sprintf("$"), -1))
	fmt.Printf("%v\n", LeftPad2Len(fmt.Sprintf("Author: %v", author), " ", 130))
	fmt.Printf("%v\n", LeftPad2Len(fmt.Sprintf("Version: %v", version), " ", 130))

}

func LineSep() string {
	return fmt.Sprintf("%v\n", LeftPad2Len("*", "*", 130))
}
