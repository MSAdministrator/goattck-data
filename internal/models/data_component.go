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
}

func NewDataComponent(object map[string]interface{}) (DataComponentObject, error) {
	dataComponent := DataComponentObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &dataComponent)
	return dataComponent, nil
}

func (d DataComponentObject) Techniques() ([]Technique, error) {
	return nil, nil
}
