package template

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"dpep/internal/protocol"
)

//go:embed templates.json
var defaultTemplatesJSON []byte

var (
	templates       map[string]string
	customTemplates map[string]string
	mu              sync.RWMutex
)

func init() {
	templates = make(map[string]string)
	if err := json.Unmarshal(defaultTemplatesJSON, &templates); err != nil {
		panic("failed to parse built-in templates: " + err.Error())
	}
}

func LoadCustomFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var custom map[string]string
	if err := json.Unmarshal(data, &custom); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if customTemplates == nil {
		customTemplates = make(map[string]string)
	}
	for k, v := range custom {
		customTemplates[k] = v
	}
	return nil
}

func Load(id string) ([]byte, error) {
	mu.RLock()
	defer mu.RUnlock()
	chainStr, ok := customTemplates[id]
	if !ok {
		chainStr, ok = templates[id]
	}
	if !ok {
		return nil, fmt.Errorf("template not found: %s", id)
	}
	return protocol.ParseHexChain(chainStr)
}

func List() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	result := make(map[string]string)
	for k, v := range templates {
		result[k] = v
	}
	for k, v := range customTemplates {
		result[k] = v
	}
	return result
}
