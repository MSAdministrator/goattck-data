package models

import (
	"encoding/json"
)

type DataComponent interface {
	Techniques() ([]Technique, error)
}

type DataComponentObject struct {
	BaseModel
	BaseAttributes
	// These are properties from the MITRE ATT&CK json
	XMitreDataSourceRef     string `json:"x_mitre_data_source_ref"`
	Type                    string `json:"type"`
	XMitreAttackSpecVersion string `json:"x_mitre_attack_spec_version"`
	XMitreModifiedByRef     string `json:"x_mitre_modified_by_ref"`
	techniques              []*TechniqueObject
}

func NewDataComponent(object map[string]interface{}) (*DataComponentObject, error) {
	dataComponent := DataComponentObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &dataComponent)
	return &dataComponent, nil
}

func (a *DataComponentObject) SetRelationships(enterprise *Enterprise) error {
	if enterprise.attackRelationshipMap[a.Id] != nil {
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

func (d DataComponentObject) Techniques() []*TechniqueObject {
	return d.techniques
}
