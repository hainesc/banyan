package version

import (
	"fmt"

	"github.com/hainesc/banyan/pkg/version"
	"github.com/spf13/cobra"
)

//VersionCmd contains first-class command for version
var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Banyan",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Banyan version: " + version.Version)
	},
}
