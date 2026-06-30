package cmd

import (
	"fmt"

	"dpep/internal/template"

	"github.com/spf13/cobra"
)

var templatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "List available templates",
	RunE: func(cmd *cobra.Command, args []string) error {
		tmpls := template.List()
		for id, chain := range tmpls {
			fmt.Printf("%s: %s\n", id, chain)
		}
		return nil
	},
}
