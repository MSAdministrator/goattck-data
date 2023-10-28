package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const attackURL = "https://raw.githubusercontent.com/swimlane/pyattck-data/main/data_collector/generated_attck_data_v3.json"

func TestEnterprise_New(t *testing.T) {
	enterprise, err := NewEnterprise(attackURL)
	if err != nil {
		t.Errorf("Error, could not load Enterprise: %v", err)
	}
	assert.IsType(t, Enterprise{}, enterprise)
	assert.Greater(t, len(enterprise.Actors), 20)
	assert.Greater(t, len(enterprise.Campaigns), 5)
	assert.Greater(t, len(enterprise.DataComponents), 5)
	assert.Greater(t, len(enterprise.DataSources), 5)
	assert.Equal(t, len(enterprise.Defintions), 1)
	assert.Greater(t, len(enterprise.Malwares), 20)
	assert.Equal(t, len(enterprise.Matrices), 1)
	assert.Greater(t, len(enterprise.Mitigations), 5)
	assert.Greater(t, len(enterprise.Relationships), 5)
	assert.Equal(t, len(enterprise.Tactics), 14)
	assert.Greater(t, len(enterprise.Techniques), 200)
	assert.Greater(t, len(enterprise.Tools), 20)

	assert.NotNil(t, enterprise.rawData)

	fakeURL := "hxxps://test.test.test/enterprise-legacy/enterprise-legacy.json"
	e, err := NewEnterprise(fakeURL)
	assert.Equal(t, Enterprise{}, e)
	assert.Error(t, err)
}

func TestEnterprise_buildRelationshipMap(t *testing.T) {
	enterprise, err := NewEnterprise(attackURL)
	if err != nil {
		t.Errorf("Error, could not load Enterprise: %v", err)
	}
	assert.Greater(t, len(enterprise.attackRelationshipMap["x-mitre-data-component--c0a4a086-cc20-4e1e-b7cb-29d99dfa3fb1"]), 25)
}
