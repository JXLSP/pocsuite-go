package api

import (
	"fmt"
)

type POCBase interface {
	GetVulID() string
	GetVersion() string
	GetAuthor() string
	GetVulDate() string
	GetCreateDate() string
	GetUpdateDate() string
	GetReferences() []string
	GetName() string
	GetAppPowerLink() string
	GetAppName() string
	GetAppVersion() string
	GetVulType() string
	GetCategory() string
	GetSamples() []string
	GetInstallRequires() []string
	GetDesc() string
	GetPocDesc() string

	// Main execution methods
	Verify(target string, options map[string]interface{}) (*Output, error)
	Attack(target string, options map[string]interface{}) (*Output, error)
	Shell(target string, options map[string]interface{}) (*Output, error)

	// Options
	GetOptions() map[string]interface{}
}

// Output represents the result of POC execution
type Output struct {
	Success bool
	Message string
	Data    map[string]interface{}
}

// NewOutput creates a new Output instance
func NewOutput() *Output {
	return &Output{
		Data: make(map[string]interface{}),
	}
}

// SuccessOutput creates a successful output
func (o *Output) SuccessOutput(data map[string]interface{}) {
	o.Success = true
	o.Message = "POC executed successfully"
	if data != nil {
		o.Data = data
	}
}

// FailOutput creates a failed output
func (o *Output) FailOutput(message string) {
	o.Success = false
	o.Message = message
}

// String returns string representation of output
func (o *Output) String() string {
	if o.Success {
		return fmt.Sprintf("[+] Success: %s\nData: %v", o.Message, o.Data)
	}
	return fmt.Sprintf("[-] Failed: %s", o.Message)
}

// POCInfo contains metadata about a POC
type POCInfo struct {
	VulID           string
	Version         string
	Author          string
	VulDate         string
	CreateDate      string
	UpdateDate      string
	References      []string
	Name            string
	AppPowerLink    string
	AppName         string
	AppVersion      string
	VulType         string
	Category        string
	Samples         []string
	InstallRequires []string
	Desc            string
	PocDesc         string
}
