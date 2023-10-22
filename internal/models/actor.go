package models

import (
	"encoding/json"
)

type Actor interface {
	Malwares() ([]Malware, error)
	Tools() ([]Tool, error)
	Techniques() ([]Technique, error)
}

type ActorObject struct {
	BaseModel
	BaseAttributes
	BaseExternalModel
	// These are properties from the MITRE ATT&CK json
	XMitreContributors []string `json:"x_mitre_contributors,omitempty"`
	// These are properties unique to pyattck-data
	actorExternalAttributes
	MitreAttckId string `json:"mitre_attck_id"`
}

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

func NewActor(object map[string]interface{}) (ActorObject, error) {
	actor := ActorObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &actor)
	return actor, nil
}

func (a *ActorObject) Malwares() ([]Malware, error) {
	return nil, nil
}

func (a *ActorObject) Tools() ([]Tool, error) {
	return nil, nil
}

func (a *ActorObject) Techniques() ([]Technique, error) {
	return nil, nil
}
