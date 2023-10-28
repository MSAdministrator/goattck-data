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
	malwares                []*MalwareObject
	techniques              []*TechniqueObject
	tools                   []*ToolObject
}

func NewCampaign(object map[string]interface{}) (*CampaignObject, error) {
	campaign := CampaignObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &campaign)
	return &campaign, nil
}

func (a *CampaignObject) SetRelationships(enterprise *Enterprise) error {
	if enterprise.attackRelationshipMap[a.Id] != nil {
		var malwares []*MalwareObject
		for _, malwareId := range enterprise.attackRelationshipMap[a.Id] {
			for _, malware := range enterprise.Malwares {
				if malware.Id == malwareId {
					malwares = append(malwares, malware)
				}
			}
		}
		a.malwares = malwares

		var techniques []*TechniqueObject
		for _, techniqueId := range enterprise.attackRelationshipMap[a.Id] {
			for _, technique := range enterprise.Techniques {
				if technique.Id == techniqueId {
					techniques = append(techniques, technique)
				}
			}
		}
		a.techniques = techniques

		var tools []*ToolObject
		for _, toolId := range enterprise.attackRelationshipMap[a.Id] {
			for _, tool := range enterprise.Tools {
				if tool.Id == toolId {
					tools = append(tools, tool)
				}
			}
		}
		a.tools = tools
	}
	return nil
}

func (c CampaignObject) Malwares() []*MalwareObject {
	return c.malwares
}

func (c CampaignObject) Techniques() []*TechniqueObject {
	return c.techniques
}

func (c CampaignObject) Tools() []*ToolObject {
	return c.tools
}
