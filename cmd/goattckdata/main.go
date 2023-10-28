package main

import (
	"fmt"

	"github.com/msadministrator/goattckdata/pkg/goattckdata"
)

func main() {
	e, err := goattckdata.NewAttck(goattckdata.DownloadURL("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"))
	if err != nil {
		fmt.Printf("Error, could not load Enterprise: %v", err)
	}
	for _, actor := range e.Actors {
		fmt.Printf("Actor: %v", actor.Name)
	}
}
