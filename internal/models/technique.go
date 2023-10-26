package models

import "encoding/json"

type Technique interface {
	Actors() ([]Actor, error)
	Campaigns() ([]Campaign, error)
	DataComponents() ([]DataComponent, error)
	DataSources() ([]DataSource, error)
	Malwares() ([]Malware, error)
	Mitigations() ([]Mitigation, error)
	Tactics() ([]Tactic, error)
	Techniques() ([]Technique, error)
	Tools() ([]Tool, error)
}

type TechniqueObject struct {
	BaseModel
	BaseAttributes
	// These are properties from the MITRE ATT&CK json
	XMitrePlatforms    []string            `json:"x_mitre_platforms"`
	ExternalReferences []ExternalReference `json:"external_references"`
	KillChainPhases    []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases"`
	XMitreDetection            string   `json:"x_mitre_detection,omitempty"`
	XMitreIsSubtechnique       bool     `json:"x_mitre_is_subtechnique"`
	XMitreModifiedByRef        string   `json:"x_mitre_modified_by_ref"`
	XMitreDataSources          []string `json:"x_mitre_data_sources,omitempty"`
	XMitreDefenseBypassed      []string `json:"x_mitre_defense_bypassed,omitempty"`
	XMitreContributors         []string `json:"x_mitre_contributors,omitempty"`
	XMitrePermissionsRequired  []string `json:"x_mitre_permissions_required,omitempty"`
	XMitreRemoteSupport        bool     `json:"x_mitre_remote_support,omitempty"`
	XMitreAttackSpecVersion    string   `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreSystemRequirements   []string `json:"x_mitre_system_requirements,omitempty"`
	XMitreImpactType           []string `json:"x_mitre_impact_type,omitempty"`
	XMitreEffectivePermissions []string `json:"x_mitre_effective_permissions,omitempty"`
	XMitreNetworkRequirements  bool     `json:"x_mitre_network_requirements,omitempty"`
	techniqueExternalAttributes
}

type techniqueExternalAttributes struct {
	// These are properties external from the MITRE ATT&CK json definitions
	CommandList        []string `json:"command_list"`
	Commands           []string `json:"commands"`
	Queries            []string `json:"queries"`
	ParsedDatasets     []string `json:"parsed_datasets"`
	PossibleDetections []string `json:"possible_detections"`
	ExternalReference  []string `json:"external_reference"`
	Controls           []string `json:"controls"`
	TechniqueId        string   `json:"technique_id"`
}

func NewTechnique(object map[string]interface{}) (TechniqueObject, error) {
	technique := TechniqueObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &technique)
	return technique, nil
}

func (t TechniqueObject) Actors() ([]Actor, error) {
	return nil, nil
}

func (t TechniqueObject) Campaigns() ([]Campaign, error) {
	return nil, nil
}

func (t TechniqueObject) DataComponents() ([]DataComponent, error) {
	return nil, nil
}

func (t TechniqueObject) DataSources() ([]DataSource, error) {
	return nil, nil
}

func (t TechniqueObject) Malwares() ([]Malware, error) {
	return nil, nil
}

func (t TechniqueObject) Mitigations() ([]Mitigation, error) {
	return nil, nil
}

func (t TechniqueObject) Tactics() ([]Tactic, error) {
	return nil, nil
}

func (t TechniqueObject) Techniques() ([]Technique, error) {
	return nil, nil
}

func (t TechniqueObject) Tools() ([]Tool, error) {
	return nil, nil
}
