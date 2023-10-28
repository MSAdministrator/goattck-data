package models

import "encoding/json"

type Matrix interface {
}

type MatrixObject struct {
	BaseModel
	Type                    string              `json:"type"`
	TacticRefs              []string            `json:"tactic_refs"`
	CreatedByRef            string              `json:"created_by_ref"`
	Description             string              `json:"description"`
	Revoked                 bool                `json:"revoked"`
	XMitreDomains           []string            `json:"x_mitre_domains"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs"`
	ExternalReferences      []ExternalReference `json:"external_references"`
	XMitreDeprecated        bool                `json:"x_mitre_deprecated"`
	XMitreVersion           string              `json:"x_mitre_version"`
	XMitreModifiedByRef     string              `json:"x_mitre_modified_by_ref"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version"`
}

func NewMatrix(object map[string]interface{}) (*MatrixObject, error) {
	matrix := MatrixObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &matrix)
	return &matrix, nil
}
