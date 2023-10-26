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
}

func NewMitigation(object map[string]interface{}) (MitigationObject, error) {
	mitigation := MitigationObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &mitigation)
	return mitigation, nil
}

func (m MitigationObject) Techniques() ([]Technique, error) {
	return nil, nil
}
