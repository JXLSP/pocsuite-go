package cmdoptions

import "github.com/spf13/cobra"

func NewRootCmd() *cobra.Command {
    return &cobra.Command{
        Use: "pocsuite",
        Short: "",
    }
}
