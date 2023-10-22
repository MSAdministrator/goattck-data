package goattckdata

import "testing"

const attackURL = "https://raw.githubusercontent.com/swimlane/pyattck-data/main/data_collector/generated_attck_data_v3.json"

func TestNewEnterprise(t *testing.T) {
	enterprise, err := NewEnterprise(attackURL)
	if err != nil {
		t.Errorf("Error, could not load Enterprise: %v", err)
	}
	if len(enterprise.Actors) == 0 {
		t.Errorf("Error, could not load Enterprise data models: %v", err)
	}
}
