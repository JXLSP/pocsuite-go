package cmdoptions

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
    Use: "pocsuite3-go",
    Short: "pocsuite-go is an open-sourced remote vulnerability testing tools ",
    Long: "pocsuite-go is an open-sourced remote vulnerability testing tools ",
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
