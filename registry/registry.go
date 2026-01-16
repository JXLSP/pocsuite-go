package registry

import (
	"fmt"
	"strings"
	"sync"

	"github.com/seaung/pocsuite-go/api"
	"github.com/seaung/pocsuite-go/yamlpoc"
)

type Registry struct {
	pocs map[string]api.POCBase
	mu   sync.RWMutex
}

var globalRegistry = &Registry{
	pocs: make(map[string]api.POCBase),
}

func Register(name string, poc api.POCBase) error {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	if _, exists := globalRegistry.pocs[name]; exists {
		return fmt.Errorf("POC '%s' already registered", name)
	}

	globalRegistry.pocs[name] = poc
	return nil
}

func Unregister(name string) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	delete(globalRegistry.pocs, name)
}

func Get(name string) (api.POCBase, bool) {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	poc, exists := globalRegistry.pocs[name]
	return poc, exists
}

func GetAll() map[string]api.POCBase {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	result := make(map[string]api.POCBase)
	for k, v := range globalRegistry.pocs {
		result[k] = v
	}
	return result
}

func Count() int {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	return len(globalRegistry.pocs)
}

func Clear() {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	globalRegistry.pocs = make(map[string]api.POCBase)
}

func Search(query string) []string {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	var results []string
	query = strings.ToLower(query)

	for name, poc := range globalRegistry.pocs {
		if strings.Contains(strings.ToLower(name), query) ||
			strings.Contains(strings.ToLower(poc.GetName()), query) ||
			strings.Contains(strings.ToLower(poc.GetDesc()), query) {
			results = append(results, name)
		}
	}

	return results
}

func ListAll() []string {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	names := make([]string, 0, len(globalRegistry.pocs))
	for name := range globalRegistry.pocs {
		names = append(names, name)
	}

	return names
}

type YAMLPOCWrapper struct {
	yamlPOC *yamlpoc.YAMLPOC
	info    *api.POCInfo
}

func NewYAMLPOCWrapper(yamlPOC *yamlpoc.YAMLPOC) *YAMLPOCWrapper {
	info := &api.POCInfo{
		Name:    yamlPOC.Info.Name,
		Author:  yamlPOC.Info.Author,
		VulType: yamlPOC.Info.Severity,
		Desc:    yamlPOC.Info.Description,
	}

	if len(yamlPOC.Info.Reference) > 0 {
		info.References = yamlPOC.Info.Reference
	}

	if len(yamlPOC.Info.Tags) > 0 {
		info.Samples = yamlPOC.Info.Tags
	}

	return &YAMLPOCWrapper{
		yamlPOC: yamlPOC,
		info:    info,
	}
}

func RegisterYAMLPOC(name string, yamlPOC *yamlpoc.YAMLPOC) error {
	wrapper := NewYAMLPOCWrapper(yamlPOC)
	return Register(name, wrapper)
}

func (w *YAMLPOCWrapper) GetVulID() string {
	return w.info.VulID
}

func (w *YAMLPOCWrapper) GetVersion() string {
	return w.info.Version
}

func (w *YAMLPOCWrapper) GetAuthor() string {
	return w.info.Author
}

func (w *YAMLPOCWrapper) GetVulDate() string {
	return w.info.VulDate
}

func (w *YAMLPOCWrapper) GetCreateDate() string {
	return w.info.CreateDate
}

func (w *YAMLPOCWrapper) GetUpdateDate() string {
	return w.info.UpdateDate
}

func (w *YAMLPOCWrapper) GetReferences() []string {
	return w.info.References
}

func (w *YAMLPOCWrapper) GetName() string {
	return w.info.Name
}

func (w *YAMLPOCWrapper) GetAppPowerLink() string {
	return w.info.AppPowerLink
}

func (w *YAMLPOCWrapper) GetAppName() string {
	return w.info.AppName
}

func (w *YAMLPOCWrapper) GetAppVersion() string {
	return w.info.AppVersion
}

func (w *YAMLPOCWrapper) GetVulType() string {
	return w.info.VulType
}

func (w *YAMLPOCWrapper) GetCategory() string {
	return w.info.Category
}

func (w *YAMLPOCWrapper) GetSamples() []string {
	return w.info.Samples
}

func (w *YAMLPOCWrapper) GetInstallRequires() []string {
	return w.info.InstallRequires
}

func (w *YAMLPOCWrapper) GetDesc() string {
	return w.info.Desc
}

func (w *YAMLPOCWrapper) GetPocDesc() string {
	return w.info.PocDesc
}

func (w *YAMLPOCWrapper) Verify(target string, options map[string]interface{}) (*api.Output, error) {
	output := api.NewOutput()

	matched, extractedData, err := w.yamlPOC.Execute(target, options)
	if err != nil {
		output.FailOutput(fmt.Sprintf("POC execution failed: %v", err))
		return output, err
	}

	if matched {
		result := make(map[string]interface{})
		result["VerifyInfo"] = map[string]interface{}{
			"URL":       target,
			"Matched":   true,
			"Extracted": extractedData,
		}
		output.SuccessOutput(result)
	} else {
		output.FailOutput("target is not vulnerable")
	}

	return output, nil
}

func (w *YAMLPOCWrapper) Attack(target string, options map[string]interface{}) (*api.Output, error) {
	output := api.NewOutput()

	matched, extractedData, err := w.yamlPOC.Execute(target, options)
	if err != nil {
		output.FailOutput(fmt.Sprintf("POC execution failed: %v", err))
		return output, err
	}

	if matched {
		result := make(map[string]interface{})
		result["AttackInfo"] = map[string]interface{}{
			"URL":       target,
			"Matched":   true,
			"Extracted": extractedData,
		}
		output.SuccessOutput(result)
	} else {
		output.FailOutput("attack failed")
	}

	return output, nil
}

func (w *YAMLPOCWrapper) Shell(target string, options map[string]interface{}) (*api.Output, error) {
	output := api.NewOutput()
	output.FailOutput("shell mode is not supported for YAML POCs")
	return output, fmt.Errorf("shell mode is not supported for YAML POCs")
}

func (w *YAMLPOCWrapper) GetOptions() map[string]interface{} {
	return make(map[string]interface{})
}
