package models

import (
	"testing"
)

func TestNewActor(t *testing.T) {
	actor, err := NewActor(loadTestJSON("actor.example.json"))
	if err != nil {
		t.Errorf("Error, could not load Actor: %v", err)
	}
	if actor.Name != "APT1" {
		t.Errorf("Error, could not load Actor data models: %v", err)
	}
	if actor.XMitreVersion != "1.4" {
		t.Errorf("Error, could not load Actor data models: %v", err)
	}
	if actor.ExternalReferences[0].SourceName != "mitre-attack" {
		t.Errorf("Error, could not load Actor data models: %v", err)
	}
}

func TestNewActor_Relationships(t *testing.T) {
	actor, err := NewActor(loadTestJSON("actor.example.json"))
	if err != nil {
		t.Errorf("Error, could not load Actor: %v", err)
	}
	malwares, err := NewMalware(loadTestJSON("malware.example.json"))
	if err != nil {
		t.Errorf("Error, could not load Actor: %v", err)
	}
	enterpriseTest := Enterprise{
		attackRelationshipMap: map[string][]string{
			"intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662": []string{
				"malware--007b44b6-e4c5-480b-b5b9-56f2081b1b7b",
			},
		},
		Malwares: []*MalwareObject{
			malwares,
		},
	}
	actor.SetRelationships(&enterpriseTest)
	if len(actor.Malwares()) != 1 {
		t.Errorf("Error, could not load Actor data models malwares relationships: %v", err)
	}

	// Now we test when there are no relationships
	actor, err = NewActor(loadTestJSON("actor.example.json"))
	if err != nil {
		t.Errorf("Error, could not load Actor: %v", err)
	}
	enterpriseTest = Enterprise{
		attackRelationshipMap: map[string][]string{
			"intrusion-set--6a2e693f-24e5-451a-9f88-testasdf": []string{
				"malware--007b44b6-e4c5-480b-b5b9-56f2081b1b7b",
			},
		},
		Malwares: []*MalwareObject{
			malwares,
		},
	}
	actor.SetRelationships(&enterpriseTest)
	if len(actor.Malwares()) != 0 {
		t.Errorf("Error, could not load Actor data models malwares relationships: %v", err)
	}
}
