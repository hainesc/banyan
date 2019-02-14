package serve

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/hainesc/banyan/pkg/config"
	"github.com/hainesc/banyan/pkg/server"
)

var (
	// ServeCmd represents the serve command
	ServeCmd = &cobra.Command{
		Use:   "serve",
		Short: "Run Banyan",
		Long: ``,
		Example: "banyan serve -f config.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			// TODO: Check flags, Init logger, grpc prometheus metrics server, TLS config
			// Read config and NewServer
			c, err := config.LoadConf("/tmp", configFile)
			if err != nil {
				// TODO: log
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			serv, _ := server.NewServer(context.Background(), c)
			// Begin serve
			if err := serv.Serve(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		},
	}
	configFile string
)

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.roster.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	ServeCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "The config file used by Banyan")
}
