package goattckdata

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/msadministrator/goattckdata/internal/models"
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
	// Whether or not this is a revoked version of the framework
	Revoked bool `json:"revoked"`
}

// Enterprise struct represents the MITRE ATT&CK Enterprise framework
type Enterprise struct {
	jsonURL        string
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
	rawData        rawEnterpriseAttck
}

func New(jsonURL string) (Enterprise, error) {
	var err error
	e := Enterprise{
		jsonURL: jsonURL,
	}
	e.rawData, err = e.download()
	if err != nil {
		slogger.Error(fmt.Sprintf("Error downloading data: %s", err))
		return e, err
	}
	err = e.loadDataModels()
	if err != nil {
		slogger.Error(fmt.Sprintf("Error loading data models: %s", err))
		return e, err
	}
	return e, err
}

func (e *Enterprise) download() (rawEnterpriseAttck, error) {
	eAttck := rawEnterpriseAttck{}

	resp, err := http.Get(e.jsonURL)
	if err != nil {
		slogger.Fatal("Unable to fetch data from URL.")
		return eAttck, err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		slogger.Fatal(fmt.Sprintf("Error reading response body: %s", readErr))
		return eAttck, readErr
	}
	bytesData := []byte(body)
	if err != nil {
		slogger.Error("Error, could not fetch data")
	}

	json.Unmarshal(bytesData, &eAttck)
	return eAttck, nil
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
