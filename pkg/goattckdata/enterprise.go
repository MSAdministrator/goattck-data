package goattckdata

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/msadministrator/goattckdata/internal/models"
)

var (
	EnterpriseAttck Enterprise
)

// The raw representation of a custom data model used by both pyattck & goattck
type rawEnterpriseAttck struct {
	// The type of framework
	Type string `json:"type"`
	// THe unique ID or hash of the JSON object
	ID string `json:"id"`
	// An array of data models structs for each entity
	Objects []interface{} `json:"objects"`
	// The defined version of the framework
	SpecVersion string `json:"spec_version"`
	// The last time the data was updated/modified.
	LastUpdated string `json:"last_updated"`
}

// Enterprise struct represents the MITRE ATT&CK Enterprise framework
type Enterprise struct {
	Actors         []models.ActorObject
	Campaigns      []models.CampaignObject
	Controls       []models.ControlObject
	DataComponents []models.DataComponentObject
	DataSources    []models.DataSourceObject
	Defintions     []models.MarkingDefinitionObject
	Malwares       []models.MalwareObject
	Matrices       []models.MatrixObject
	Mitigations    []models.MitigationObject
	Relationships  []models.RelationshipObject
	Tactics        []models.TacticObject
	Techniques     []models.TechniqueObject
	Tools          []models.ToolObject
	rawData        *rawEnterpriseAttck
}

// Fetch MITRE ATT&CK data and unmarshal into rawEnterpriseAttck struct
func (e *Enterprise) Download(url DownloadURL) error {
	slogger.Info("Fetching MITRE ATT&CK...")
	resp, err := http.Get(string(url))
	if err != nil {
		slogger.Warning("Unable to fetch data from URL.")
		return err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		slogger.Fatal(fmt.Sprintf("Error reading response body: %s", readErr))
		return readErr
	}
	bytesData := []byte(body)
	if err != nil {
		slogger.Error("Error, could not fetch data")
	}
	eAttck := rawEnterpriseAttck{}
	json.Unmarshal(bytesData, &eAttck)
	e.rawData = &eAttck
	return nil
}

// Load data models from rawEnterpriseAttck struct
func (e *Enterprise) loadDataModels() error {
	for _, value := range e.rawData.Objects {
		v, ok := value.(map[string]interface{})
		if !ok {
			slogger.Error("error casting value to map")
		}
		switch v["type"] {
		case "intrusion-set":
			actor, err := models.NewActor(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating actor: %s", err))
			}
			e.Actors = append(e.Actors, actor)
		case "campaign":
			campaign, err := models.NewCampaign(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating campaign: %s", err))
			}
			e.Campaigns = append(e.Campaigns, campaign)
		case "x-mitre-data-component":
			dataComponent, err := models.NewDataComponent(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating data component: %s", err))
			}
			e.DataComponents = append(e.DataComponents, dataComponent)
		case "x-mitre-data-source":
			dataSource, err := models.NewDataSource(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating data source: %s", err))
			}
			e.DataSources = append(e.DataSources, dataSource)
		case "marking-definition":
			markingDefinition, err := models.NewMarkingDefinition(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating marking definition: %s", err))
			}
			e.Defintions = append(e.Defintions, markingDefinition)
		case "malware":
			malware, err := models.NewMalware(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating malware: %s", err))
			}
			e.Malwares = append(e.Malwares, malware)
		case "course-of-action":
			mitigation, err := models.NewMitigation(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating mitigation: %s", err))
			}
			e.Mitigations = append(e.Mitigations, mitigation)
		case "x-mitre-matrix":
			matrix, err := models.NewMatrix(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating matrix: %s", err))
			}
			e.Matrices = append(e.Matrices, matrix)
		case "relationship":
			relationship, err := models.NewRelationship(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating relationship: %s", err))
			}
			e.Relationships = append(e.Relationships, relationship)
		case "x-mitre-tactic":
			tactic, err := models.NewTactic(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating tactic: %s", err))
			}
			e.Tactics = append(e.Tactics, tactic)
		case "attack-pattern":
			technique, err := models.NewTechnique(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating technique: %s", err))
			}
			e.Techniques = append(e.Techniques, technique)
		case "tool":
			tool, err := models.NewTool(v)
			if err != nil {
				slogger.Error(fmt.Sprintf("Error creating tool: %s", err))
			}
			e.Tools = append(e.Tools, tool)
		}
	}
	return nil
}
