package models

import (
	"github.com/msadministrator/goattckdata/internal/logger"
)

var (
	slogger = logger.NewLogger(logger.Info, true)
)

// The raw representation of a custom data model used by both pyattck & goattck
type rawEnterpriseAttck struct {
	// The type of framework
	Type string `json:"type"`
	// THe unique ID or hash of the JSON object
	ID string `json:"id"`
	// An array of data models structs for each entity
	Objects []interface{} `json:"objects"`
	// The defined version of the framework
	SpecVersion string `json:"spec_version"`
	// The last time the data was updated/modified.
	LastUpdated string `json:"last_updated"`
}
