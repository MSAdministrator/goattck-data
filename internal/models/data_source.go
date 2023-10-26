package models

import "encoding/json"

type DataSource interface {
	DataComponents() ([]DataComponent, error)
	Techniques() ([]Technique, error)
}

type DataSourceObject struct {
	BaseModel
	BaseAttributes
	BaseExternalModel
	// These are properties from the MITRE ATT&CK json
	XMitrePlatforms         []string            `json:"x_mitre_platforms"`
	XMitreContributors      []string            `json:"x_mitre_contributors,omitempty"`
	XMitreCollectionLayers  []string            `json:"x_mitre_collection_layers"`
	ExternalReferences      []ExternalReference `json:"external_references"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version"`
	XMitreModifiedByRef     string              `json:"x_mitre_modified_by_ref"`
}

func NewDataSource(object map[string]interface{}) (DataSourceObject, error) {
	dataSource := DataSourceObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &dataSource)
	return dataSource, nil
}

func (d DataSourceObject) DataComponents() ([]DataComponent, error) {
	return nil, nil
}

func (d DataSourceObject) Techniques() ([]Technique, error) {
	return nil, nil
}
