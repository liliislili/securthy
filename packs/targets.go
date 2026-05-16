package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Targets struct {
	Windows         []string `json:"windows"`
	Linux           []string `json:"linux"`
	RecommendedTier string   `json:"recommended_tier"`
	ISOScore        int      `json:"iso_score"`
	ISOGrade        string   `json:"iso_grade"`
}

type WinCreds struct {
	User string
	Pass string
}

func loadTargets(path string) (*Targets, error) {
	if path == "" {
		path = "targets.json"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("targets.json not found\n\n" +
				"  Run the scanner first:\n" +
				"  go run ./cmd 192.168.1.0/24\n\n" +
				"  It generates targets.json automatically with the recommended pack tier.")
		}
		return nil, err
	}

	var targets Targets
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, fmt.Errorf("invalid targets.json: %w", err)
	}

	return &targets, nil
}
