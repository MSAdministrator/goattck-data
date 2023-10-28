package models

import (
	"encoding/json"
)

type Actor interface {
	Malwares() ([]Malware, error)
	Tools() ([]Tool, error)
	Techniques() ([]Technique, error)
}

// ActorObject is a representation of the MITRE ATT&CK Actor json model
type ActorObject struct {
	BaseModel
	BaseAttributes
	BaseExternalModel
	// These are properties from the MITRE ATT&CK json
	XMitreContributors []string `json:"x_mitre_contributors,omitempty"`
	// These are properties unique to pyattck-data
	actorExternalAttributes
	MitreAttckId string `json:"mitre_attck_id"`
	malwares     []*MalwareObject
	tools        []*ToolObject
	techniques   []*TechniqueObject
}

// actorExternalAttributes are properties external from the MITRE ATT&CK json definitions
type actorExternalAttributes struct {
	Names               []string `json:"names"`
	ExternalTools       []string `json:"external_tools"`
	Country             []string `json:"country"`
	Operations          []string `json:"operations"`
	Links               []string `json:"links"`
	Targets             []string `json:"targets"`
	ExternalDescription []string `json:"external_description"`
	AttckID             string   `json:"attck_id"`
	Comment             string   `json:"comment"`
	Comments            []string `json:"comments"`
}

// NewActor is a function that takes in a map of data and returns a ActorObject
func NewActor(object map[string]interface{}) (*ActorObject, error) {
	actor := ActorObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &actor)
	return &actor, nil
}

func (a *ActorObject) SetRelationships(enterprise *Enterprise) error {
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
		var tools []*ToolObject
		for _, toolId := range enterprise.attackRelationshipMap[a.Id] {
			for _, tool := range enterprise.Tools {
				if tool.Id == toolId {
					tools = append(tools, tool)
				}
			}
		}
		a.tools = tools
		var techniques []*TechniqueObject
		for _, techniqueId := range enterprise.attackRelationshipMap[a.Id] {
			for _, technique := range enterprise.Techniques {
				if technique.Id == techniqueId {
					techniques = append(techniques, technique)
				}
			}
		}
		a.techniques = techniques
	}
	return nil
}

func (a ActorObject) Malwares() []*MalwareObject {
	return a.malwares
}

func (a ActorObject) Tools() []*ToolObject {
	return a.tools
}

func (a ActorObject) Techniques() []*TechniqueObject {
	return a.techniques
}
