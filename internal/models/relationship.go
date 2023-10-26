package models

import "encoding/json"

type Relationship interface {
}

type RelationshipObject struct {
	BaseAttributes
	Id                      string              `json:"id"`
	Type                    string              `json:"type"`
	Created                 string              `json:"created"`
	Modified                string              `json:"modified"`
	SourceRef               string              `json:"source_ref"`
	TargetRef               string              `json:"target_ref"`
	RelationshipType        string              `json:"relationship_type"`
	XMitreVersion           string              `json:"x_mitre_version"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version"`
	ExternalReferences      []ExternalReference `json:"external_references"`
	XMitreModifiedByRef     string              `json:"x_mitre_modified_by_ref"`
}

func NewRelationship(object map[string]interface{}) (RelationshipObject, error) {
	relationship := RelationshipObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &relationship)
	return relationship, nil
}
