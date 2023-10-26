package models

import (
	"encoding/json"
	"time"
)

type Campaign interface {
	Malwares() ([]Malware, error)
	Tools() ([]Tool, error)
	Techniques() ([]Technique, error)
}

type CampaignObject struct {
	BaseModel
	BaseAttributes
	BaseExternalModel
	// These are properties from the MITRE ATT&CK json
	FirstSeen               time.Time `json:"first_seen"`
	LastSeen                time.Time `json:"last_seen"`
	XMitreFirstSeenCitation string    `json:"x_mitre_first_seen_citation"`
	XMitreLastSeenCitation  string    `json:"x_mitre_last_seen_citation"`
	XMitreContributors      []string  `json:"x_mitre_contributors,omitempty"`
}

func NewCampaign(object map[string]interface{}) (CampaignObject, error) {
	campaign := CampaignObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &campaign)
	return campaign, nil
}

func (c CampaignObject) Malwares() ([]Malware, error) {
	return nil, nil
}

func (c CampaignObject) Tools() ([]Tool, error) {
	return nil, nil
}

func (c CampaignObject) Techniques() ([]Technique, error) {
	return nil, nil
}
