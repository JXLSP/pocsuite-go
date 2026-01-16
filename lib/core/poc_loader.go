package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/seaung/pocsuite-go/registry"
	"github.com/seaung/pocsuite-go/yamlpoc"
)

type POCLoader struct {
	loadedPOCs map[string]bool
}

func NewPOCLoader() *POCLoader {
	return &POCLoader{
		loadedPOCs: make(map[string]bool),
	}
}

func (pl *POCLoader) LoadFromFile(pocPath string) (string, error) {
	if _, err := os.Stat(pocPath); os.IsNotExist(err) {
		return "", fmt.Errorf("POC file does not exist: %s", pocPath)
	}

	yamlPOC, err := yamlpoc.ParseFile(pocPath)
	if err != nil {
		return "", fmt.Errorf("failed to parse POC: %w", err)
	}

	pocName := filepath.Base(pocPath)
	pocName = strings.TrimSuffix(pocName, filepath.Ext(pocName))

	if _, exists := pl.loadedPOCs[pocName]; exists {
		return pocName, fmt.Errorf("POC '%s' is already loaded", pocName)
	}

	if err := registry.RegisterYAMLPOC(pocName, yamlPOC); err != nil {
		return "", fmt.Errorf("failed to register POC: %w", err)
	}

	pl.loadedPOCs[pocName] = true

	return pocName, nil
}

func (pl *POCLoader) LoadFromDir(dir string) ([]string, error) {
	var loadedPOCs []string

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("POC directory does not exist: %s", dir)
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		pocName, err := pl.LoadFromFile(path)
		if err != nil {
			fmt.Printf("Warning: Failed to load POC from %s: %v\n", path, err)
			return nil
		}

		loadedPOCs = append(loadedPOCs, pocName)

		return nil
	})

	if err != nil {
		return loadedPOCs, fmt.Errorf("failed to walk directory: %w", err)
	}

	return loadedPOCs, nil
}

func (pl *POCLoader) LoadFromFiles(pocPaths []string) ([]string, error) {
	var loadedPOCs []string

	for _, pocPath := range pocPaths {
		pocName, err := pl.LoadFromFile(pocPath)
		if err != nil {
			fmt.Printf("Warning: Failed to load POC from %s: %v\n", pocPath, err)
			continue
		}

		loadedPOCs = append(loadedPOCs, pocName)
	}

	return loadedPOCs, nil
}

func (pl *POCLoader) GetLoadedPOCs() []string {
	pocs := make([]string, 0, len(pl.loadedPOCs))
	for name := range pl.loadedPOCs {
		pocs = append(pocs, name)
	}
	return pocs
}

func (pl *POCLoader) IsLoaded(pocName string) bool {
	_, exists := pl.loadedPOCs[pocName]
	return exists
}

func (pl *POCLoader) Unload(pocName string) error {
	if !pl.IsLoaded(pocName) {
		return fmt.Errorf("POC '%s' is not loaded", pocName)
	}

	registry.Unregister(pocName)

	delete(pl.loadedPOCs, pocName)

	return nil
}

func (pl *POCLoader) Clear() {
	for pocName := range pl.loadedPOCs {
		registry.Unregister(pocName)
	}
	pl.loadedPOCs = make(map[string]bool)
}

func (pl *POCLoader) Count() int {
	return len(pl.loadedPOCs)
}
