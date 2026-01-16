package plugins

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type FileRecordPlugin struct {
	*PluginBase
	filename string
	file     *os.File
	mu       sync.Mutex
}

func NewFileRecordPlugin(filename string) *FileRecordPlugin {
	return &FileRecordPlugin{
		PluginBase: NewPluginBase(CategoryResults, "file_record"),
		filename:   filename,
	}
}

func (p *FileRecordPlugin) Init() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.filename == "" {
		p.filename = fmt.Sprintf("pocsuite_results_%s.json", time.Now().Format("20060102_150405"))
	}

	file, err := os.OpenFile(p.filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	p.file = file

	if _, err := p.file.WriteString("[\n"); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

func (p *FileRecordPlugin) Start() error {
	return nil
}

func (p *FileRecordPlugin) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.file != nil {
		if _, err := p.file.WriteString("\n]\n"); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		if err := p.file.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}
		p.file = nil
	}
	return nil
}

func (p *FileRecordPlugin) Handle(output interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.file == nil {
		return fmt.Errorf("file not initialized")
	}

	data, err := json.MarshalIndent(output, "  ", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	if _, err := p.file.WriteString("  " + string(data) + ",\n"); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

func (p *FileRecordPlugin) AddResult(result interface{}) error {
	return p.Handle(result)
}

func (p *FileRecordPlugin) GetResults() []interface{} {
	return nil
}

func (p *FileRecordPlugin) Export(filename string) error {
	return fmt.Errorf("file_record plugin exports to file automatically")
}

type HTMLReportPlugin struct {
	*PluginBase
	results []interface{}
	mu      sync.Mutex
}

func NewHTMLReportPlugin() *HTMLReportPlugin {
	return &HTMLReportPlugin{
		PluginBase: NewPluginBase(CategoryResults, "html_report"),
		results:    make([]interface{}, 0),
	}
}

func (p *HTMLReportPlugin) Init() error {
	return nil
}

func (p *HTMLReportPlugin) Start() error {
	return nil
}

func (p *HTMLReportPlugin) Stop() error {
	return nil
}

func (p *HTMLReportPlugin) Handle(output interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.results = append(p.results, output)
	return nil
}

func (p *HTMLReportPlugin) AddResult(result interface{}) error {
	return p.Handle(result)
}

func (p *HTMLReportPlugin) GetResults() []interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	results := make([]interface{}, len(p.results))
	copy(results, p.results)
	return results
}

func (p *HTMLReportPlugin) Export(filename string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if filename == "" {
		filename = fmt.Sprintf("pocsuite_report_%s.html", time.Now().Format("20060102_150405"))
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pocsuite3 Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #e8f5e9;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .result {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            background-color: #fafafa;
        }
        .result.success {
            border-left: 4px solid #4CAF50;
        }
        .result.failure {
            border-left: 4px solid #f44336;
        }
        .result.info {
            border-left: 4px solid #2196F3;
        }
        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
        }
        .timestamp {
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Pocsuite3 Report</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p>Total Results: ` + fmt.Sprintf("%d", len(p.results)) + `</p>
            <p>Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        </div>
        <h2>Results</h2>
`

	if _, err := file.WriteString(html); err != nil {
		return fmt.Errorf("failed to write HTML header: %w", err)
	}

	for i, result := range p.results {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			continue
		}

		resultHTML := fmt.Sprintf(`
        <div class="result info">
            <h3>Result #%d</h3>
            <p class="timestamp">Generated: %s</p>
            <pre>%s</pre>
        </div>
`, i+1, time.Now().Format("2006-01-02 15:04:05"), string(data))

		if _, err := file.WriteString(resultHTML); err != nil {
			return fmt.Errorf("failed to write result: %w", err)
		}
	}

	footer := `
    </div>
</body>
</html>
`

	if _, err := file.WriteString(footer); err != nil {
		return fmt.Errorf("failed to write HTML footer: %w", err)
	}

	return nil
}

type ConsoleOutputPlugin struct {
	*PluginBase
}

func NewConsoleOutputPlugin() *ConsoleOutputPlugin {
	return &ConsoleOutputPlugin{
		PluginBase: NewPluginBase(CategoryResults, "console_output"),
	}
}

func (p *ConsoleOutputPlugin) Init() error {
	return nil
}

func (p *ConsoleOutputPlugin) Start() error {
	return nil
}

func (p *ConsoleOutputPlugin) Stop() error {
	return nil
}

func (p *ConsoleOutputPlugin) Handle(output interface{}) error {
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func (p *ConsoleOutputPlugin) AddResult(result interface{}) error {
	return p.Handle(result)
}

func (p *ConsoleOutputPlugin) GetResults() []interface{} {
	return nil
}

func (p *ConsoleOutputPlugin) Export(filename string) error {
	return fmt.Errorf("console_output plugin does not support export")
}
