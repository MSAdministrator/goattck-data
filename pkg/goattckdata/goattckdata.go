package goattckdata

import (
	"github.com/msadministrator/goattckdata/internal/logger"
	"github.com/msadministrator/goattckdata/internal/models"
)

type DownloadURL string

var (
	slogger = logger.NewLogger(logger.Info, true)
)

// Creates and loads the Enterprise MITRE ATT&CK framework into defined models
func NewAttck(url DownloadURL) (models.Enterprise, error) {
	enterprise, err := models.NewEnterprise(string(url))
	if err != nil {
		slogger.Fatal("Error, could not load Enterprise")
	}
	return enterprise, nil
}
