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
	actors         []*ActorObject
	campaigns      []*CampaignObject
	dataComponents []*DataComponentObject
	dataSources    []*DataSourceObject
	malwares       []*MalwareObject
	mitigations    []*MitigationObject
	tactics        []*TacticObject
	techniques     []*TechniqueObject
	tools          []*ToolObject
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

func NewTechnique(object map[string]interface{}) (*TechniqueObject, error) {
	technique := TechniqueObject{}
	jsonString, _ := json.Marshal(object)
	json.Unmarshal(jsonString, &technique)
	return &technique, nil
}

func (a *TechniqueObject) SetRelationships(enterprise *Enterprise) error {
	if enterprise.attackRelationshipMap[a.Id] != nil {
		var actors []*ActorObject
		for _, actorId := range enterprise.attackRelationshipMap[a.Id] {
			for _, actor := range enterprise.Actors {
				if actor.Id == actorId {
					actors = append(actors, actor)
				}
			}
		}
		a.actors = actors
		var campaigns []*CampaignObject
		for _, campaignId := range enterprise.attackRelationshipMap[a.Id] {
			for _, campaign := range enterprise.Campaigns {
				if campaign.Id == campaignId {
					campaigns = append(campaigns, campaign)
				}
			}
		}
		a.campaigns = campaigns

		var dataComponents []*DataComponentObject
		for _, dataComponentId := range enterprise.attackRelationshipMap[a.Id] {
			for _, dataComponent := range enterprise.DataComponents {
				if dataComponent.Id == dataComponentId {
					dataComponents = append(dataComponents, dataComponent)
				}
			}
		}
		a.dataComponents = dataComponents

		var dataSources []*DataSourceObject
		for _, dataSourceId := range enterprise.attackRelationshipMap[a.Id] {
			for _, dataSource := range enterprise.DataSources {
				if dataSource.Id == dataSourceId {
					dataSources = append(dataSources, dataSource)
				}
			}
		}
		a.dataSources = dataSources

		var malwares []*MalwareObject
		for _, malwareId := range enterprise.attackRelationshipMap[a.Id] {
			for _, malware := range enterprise.Malwares {
				if malware.Id == malwareId {
					malwares = append(malwares, malware)
				}
			}
		}
		a.malwares = malwares

		var tactics []*TacticObject
		for _, phase := range a.KillChainPhases {
			for _, tactic := range enterprise.Tactics {
				if tactic.XMitreShortname == phase.KillChainName {
					tactics = append(tactics, tactic)
				}
			}
		}
		a.tactics = tactics

		var techniques []*TechniqueObject
		for _, techniqueId := range enterprise.attackRelationshipMap[a.Id] {
			for _, technique := range enterprise.Techniques {
				if technique.Id == techniqueId {
					techniques = append(techniques, technique)
				}
			}
		}
		a.techniques = techniques

		var tools []*ToolObject
		for _, toolId := range enterprise.attackRelationshipMap[a.Id] {
			for _, tool := range enterprise.Tools {
				if tool.Id == toolId {
					tools = append(tools, tool)
				}
			}
		}
		a.tools = tools
	}
	return nil
}

func (t TechniqueObject) Actors() []*ActorObject {
	return t.actors
}

func (t TechniqueObject) Campaigns() []*CampaignObject {
	return t.campaigns
}

func (t TechniqueObject) DataComponents() []*DataComponentObject {
	return t.dataComponents
}

func (t TechniqueObject) DataSources() []*DataSourceObject {
	return t.dataSources
}

func (t TechniqueObject) Malwares() []*MalwareObject {
	return t.malwares
}

func (t TechniqueObject) Mitigations() []*MitigationObject {
	return t.mitigations
}

func (t TechniqueObject) Tactics() []*TacticObject {
	return t.tactics
}

func (t TechniqueObject) Techniques() []*TechniqueObject {
	return t.techniques
}

func (t TechniqueObject) Tools() []*ToolObject {
	return t.tools
}
