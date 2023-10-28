package models

import "encoding/json"

type MarkingDefinition interface {
}

type MarkingDefinitionObject struct {
	BaseModel
	// These are properties from the MITRE ATT&CK json
	Definition struct {
		Statement string `json:"statement"`
	} `json:"definition"`
	CreatedByRef            string `json:"created_by_ref"`
	DefinitionType          string `json:"definition_type"`
	XMitreAttackSpecVersion string `json:"x_mitre_attack_spec_version"`
}

func NewMarkingDefinition(object map[string]interface{}) (*MarkingDefinitionObject, error) {
	definition := MarkingDefinitionObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &definition)
	return &definition, nil
}
