package goattckdata

import (
	"github.com/msadministrator/goattck/internal/logger"
)

const attackURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

type DownloadURL string

var (
	slogger = logger.NewLogger(logger.Info, true)
)

// Creates and loads the Enterprise MITRE ATT&CK framework into defined models
func NewEnterprise(url DownloadURL) (Enterprise, error) {

	enterprise := &Enterprise{}
	err := enterprise.Download(url)
	if err != nil {
		slogger.Fatal("Error, could not load Enterprise")
	}
	err = enterprise.loadDataModels()
	if err != nil {
		slogger.Error("Error, could not load Enterprise data models")
	}
	EnterpriseAttck = *enterprise
	return *enterprise, nil
}
