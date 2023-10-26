package models

import "encoding/json"

type Tactic interface {
	Techniques() ([]Technique, error)
}

type TacticObject struct {
	BaseModel
	// These are properties from the MITRE ATT&CK json
	ObjectMarkingRefs       []string            `json:"object_marking_refs"`
	CreatedByRef            string              `json:"created_by_ref"`
	ExternalReferences      []ExternalReference `json:"external_references"`
	Description             string              `json:"description"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version"`
	XMitreModifiedByRef     string              `json:"x_mitre_modified_by_ref"`
	XMitreShortname         string              `json:"x_mitre_shortname"`
}

func NewTactic(object map[string]interface{}) (TacticObject, error) {
	tactic := TacticObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &tactic)
	return tactic, nil
}

func (t TacticObject) Techniques() ([]Technique, error) {
	return nil, nil
}
