package main

import (
	"dpep/cmd"
	"dpep/gui"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--gui" {
		gui.Start()
		return
	}
	cmd.Execute()
}
