package models

import "encoding/json"

type Mitigation interface {
	Techniques() ([]Technique, error)
}

type MitigationObject struct {
	BaseModel
	BaseAttributes
	// These are properties from the MITRE ATT&CK json
	ExternalReferences      []ExternalReference `json:"external_references"`
	XMitreModifiedByRef     string              `json:"x_mitre_modified_by_ref"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	techniques              []*TechniqueObject
}

func NewMitigation(object map[string]interface{}) (*MitigationObject, error) {
	mitigation := MitigationObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &mitigation)
	return &mitigation, nil
}

func (a *MitigationObject) SetRelationships(enterprise *Enterprise) error {
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

func (m MitigationObject) Techniques() []*TechniqueObject {
	return m.techniques
}
