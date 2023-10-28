package models

import "encoding/json"

type Control interface {
	Techniques() ([]Technique, error)
}

type ControlObject struct {
	// Base fields
	BaseModel
	// Fields
	Revoked            bool                `json:"revoked"`
	XMitreFamily       string              `json:"x_mitre_family"`
	XMitreImpact       []string            `json:"x_mitre_impact"`
	XMitrePriority     string              `json:"x_mitre_priority"`
	ObjectMarkingRefs  []string            `json:"object_marking_refs"`
	ExternalReferences []ExternalReference `json:"external_references"`
}

func NewControl(object map[string]interface{}) (ControlObject, error) {
	control := ControlObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &control)
	return control, nil
}

func (c ControlObject) Techniques() ([]Technique, error) {
	return nil, nil
}
