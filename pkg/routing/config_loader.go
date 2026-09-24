package routing

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type configFile struct {
	Routes []Route `yaml:"routes"`
}

func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read routes config: %w", err)
	}

	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse routes config: %w", err)
	}

	return NewRegistry(cfg.Routes)
}
