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
	dataComponents          []*DataComponentObject
	techniques              []*TechniqueObject
}

func NewDataSource(object map[string]interface{}) (*DataSourceObject, error) {
	dataSource := DataSourceObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &dataSource)
	return &dataSource, nil
}

func (a *DataSourceObject) SetRelationships(enterprise *Enterprise) error {
	if enterprise.attackRelationshipMap[a.Id] != nil {
		var dataComponents []*DataComponentObject
		for _, dataComponentId := range enterprise.attackRelationshipMap[a.Id] {
			for _, dataComponent := range enterprise.DataComponents {
				if dataComponent.Id == dataComponentId {
					dataComponents = append(dataComponents, dataComponent)
				}
			}
		}
		a.dataComponents = dataComponents

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

func (d DataSourceObject) DataComponents() []*DataComponentObject {
	return d.dataComponents
}

func (d DataSourceObject) Techniques() []*TechniqueObject {
	return d.techniques
}
