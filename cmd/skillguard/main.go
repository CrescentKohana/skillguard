// Command skillguard is the SkillGuard static-analysis CLI.
package main

import (
	"os"

	"github.com/CrescentKohana/skillguard/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
