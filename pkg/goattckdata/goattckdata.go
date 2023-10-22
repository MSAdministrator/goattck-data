package goattckdata

import (
	"github.com/msadministrator/goattckdata/internal/logger"
)

type DownloadURL string

var (
	slogger = logger.NewLogger(logger.Info, true)
)

// Creates and loads the Enterprise MITRE ATT&CK framework into defined models
func NewEnterprise(url DownloadURL) (Enterprise, error) {
	enterprise, err := New(string(url))
	if err != nil {
		slogger.Fatal("Error, could not load Enterprise")
	}
	err = enterprise.loadDataModels()
	if err != nil {
		slogger.Error("Error, could not load Enterprise data models")
	}
	//EnterpriseAttck = *enterprise
	return enterprise, nil
}
