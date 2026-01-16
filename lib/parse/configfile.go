package parse

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type ConfigFile struct {
	sections map[string]map[string]string
}

func NewConfigFile() *ConfigFile {
	return &ConfigFile{
		sections: make(map[string]map[string]string),
	}
}

func (cf *ConfigFile) Parse(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file '%s' does not exist", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open configuration file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentSection string
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			if currentSection == "" {
				return fmt.Errorf("invalid section name at line %d", lineNumber)
			}
			if _, exists := cf.sections[currentSection]; !exists {
				cf.sections[currentSection] = make(map[string]string)
			}
			continue
		}

		if currentSection == "" {
			return fmt.Errorf("key-value pair found outside of section at line %d", lineNumber)
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid key-value pair at line %d", lineNumber)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
			value = value[1 : len(value)-1]
		} else if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
			value = value[1 : len(value)-1]
		}

		cf.sections[currentSection][key] = value
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading configuration file: %w", err)
	}

	if _, exists := cf.sections["Target"]; !exists {
		return fmt.Errorf("missing mandatory section 'Target' in configuration file")
	}

	return nil
}

func (cf *ConfigFile) HasSection(section string) bool {
	_, exists := cf.sections[section]
	return exists
}

func (cf *ConfigFile) HasOption(section, option string) bool {
	if !cf.HasSection(section) {
		return false
	}
	_, exists := cf.sections[section][option]
	return exists
}

func (cf *ConfigFile) GetString(section, option string) (string, error) {
	if !cf.HasOption(section, option) {
		return "", fmt.Errorf("option '%s' not found in section '%s'", option, section)
	}
	return cf.sections[section][option], nil
}

func (cf *ConfigFile) GetStringDefault(section, option, defaultValue string) string {
	value, err := cf.GetString(section, option)
	if err != nil {
		return defaultValue
	}
	return value
}

func (cf *ConfigFile) GetBool(section, option string) (bool, error) {
	value, err := cf.GetString(section, option)
	if err != nil {
		return false, err
	}

	value = strings.ToLower(value)
	switch value {
	case "true", "yes", "1", "on":
		return true, nil
	case "false", "no", "0", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", value)
	}
}

func (cf *ConfigFile) GetBoolDefault(section, option string, defaultValue bool) bool {
	value, err := cf.GetBool(section, option)
	if err != nil {
		return defaultValue
	}
	return value
}

func (cf *ConfigFile) GetInt(section, option string) (int, error) {
	value, err := cf.GetString(section, option)
	if err != nil {
		return 0, err
	}

	result, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid integer value: %s", value)
	}
	return result, nil
}

func (cf *ConfigFile) GetIntDefault(section, option string, defaultValue int) int {
	value, err := cf.GetInt(section, option)
	if err != nil {
		return defaultValue
	}
	return value
}

func (cf *ConfigFile) GetInt64(section, option string) (int64, error) {
	value, err := cf.GetString(section, option)
	if err != nil {
		return 0, err
	}

	result, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid int64 value: %s", value)
	}
	return result, nil
}

func (cf *ConfigFile) GetInt64Default(section, option string, defaultValue int64) int64 {
	value, err := cf.GetInt64(section, option)
	if err != nil {
		return defaultValue
	}
	return value
}

func (cf *ConfigFile) GetFloat64(section, option string) (float64, error) {
	value, err := cf.GetString(section, option)
	if err != nil {
		return 0, err
	}

	result, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid float64 value: %s", value)
	}
	return result, nil
}

func (cf *ConfigFile) GetFloat64Default(section, option string, defaultValue float64) float64 {
	value, err := cf.GetFloat64(section, option)
	if err != nil {
		return defaultValue
	}
	return value
}

func (cf *ConfigFile) GetSections() []string {
	sections := make([]string, 0, len(cf.sections))
	for section := range cf.sections {
		sections = append(sections, section)
	}
	return sections
}

func (cf *ConfigFile) GetOptions(section string) []string {
	if !cf.HasSection(section) {
		return []string{}
	}

	options := make([]string, 0, len(cf.sections[section]))
	for option := range cf.sections[section] {
		options = append(options, option)
	}
	return options
}

func (cf *ConfigFile) GetAllOptions(section string) map[string]string {
	if !cf.HasSection(section) {
		return make(map[string]string)
	}

	result := make(map[string]string)
	for key, value := range cf.sections[section] {
		result[key] = value
	}
	return result
}

func (cf *ConfigFile) SetOption(section, option, value string) {
	if _, exists := cf.sections[section]; !exists {
		cf.sections[section] = make(map[string]string)
	}
	cf.sections[section][option] = value
}

func (cf *ConfigFile) RemoveOption(section, option string) {
	if cf.HasOption(section, option) {
		delete(cf.sections[section], option)
	}
}

func (cf *ConfigFile) RemoveSection(section string) {
	if cf.HasSection(section) {
		delete(cf.sections, section)
	}
}

func (cf *ConfigFile) Save(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create configuration file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for section, options := range cf.sections {
		if _, err := writer.WriteString(fmt.Sprintf("[%s]\n", section)); err != nil {
			return err
		}

		for key, value := range options {
			if strings.ContainsAny(value, " \t\n\r\"'") {
				value = fmt.Sprintf("\"%s\"", value)
			}
			if _, err := writer.WriteString(fmt.Sprintf("%s = %s\n", key, value)); err != nil {
				return err
			}
		}

		if _, err := writer.WriteString("\n"); err != nil {
			return err
		}
	}

	return nil
}

func (cf *ConfigFile) Merge(other *ConfigFile) {
	for section, options := range other.sections {
		if _, exists := cf.sections[section]; !exists {
			cf.sections[section] = make(map[string]string)
		}
		for key, value := range options {
			cf.sections[section][key] = value
		}
	}
}

func (cf *ConfigFile) Clone() *ConfigFile {
	clone := NewConfigFile()
	for section, options := range cf.sections {
		clone.sections[section] = make(map[string]string)
		for key, value := range options {
			clone.sections[section][key] = value
		}
	}
	return clone
}

func ParseConfigFile(filePath string) (*ConfigFile, error) {
	cf := NewConfigFile()
	err := cf.Parse(filePath)
	if err != nil {
		return nil, err
	}
	return cf, nil
}

func ConfigFileParser(configFile string, config *Config) error {
	cf := NewConfigFile()
	if err := cf.Parse(configFile); err != nil {
		return err
	}

	if cf.HasSection("Target") {
		if cf.HasOption("Target", "url") {
			if url := cf.GetStringDefault("Target", "url", ""); url != "" {
				config.URLs = append(config.URLs, url)
			}
		}
		if cf.HasOption("Target", "file") {
			config.URLFile = cf.GetStringDefault("Target", "file", "")
		}
		if cf.HasOption("Target", "poc") {
			if poc := cf.GetStringDefault("Target", "poc", ""); poc != "" {
				config.POC = append(config.POC, poc)
			}
		}
		if cf.HasOption("Target", "mode") {
			config.Mode = cf.GetStringDefault("Target", "mode", "verify")
		}
	}

	if cf.HasSection("Request") {
		config.Cookie = cf.GetStringDefault("Request", "cookie", config.Cookie)
		config.Host = cf.GetStringDefault("Request", "host", config.Host)
		config.Referer = cf.GetStringDefault("Request", "referer", config.Referer)
		config.UserAgent = cf.GetStringDefault("Request", "user-agent", config.UserAgent)
		config.Proxy = cf.GetStringDefault("Request", "proxy", config.Proxy)
		config.ProxyCred = cf.GetStringDefault("Request", "proxy-cred", config.ProxyCred)
		config.Timeout = cf.GetFloat64Default("Request", "timeout", config.Timeout)
		config.Retry = cf.GetIntDefault("Request", "retry", config.Retry)
		config.Headers = cf.GetStringDefault("Request", "headers", config.Headers)
		config.SessionReuse = cf.GetBoolDefault("Request", "session-reuse", config.SessionReuse)
	}

	if cf.HasSection("Optimization") {
		config.OutputPath = cf.GetStringDefault("Optimization", "output", config.OutputPath)
		config.Plugins = cf.GetStringDefault("Optimization", "plugins", config.Plugins)
		config.POCsPath = cf.GetStringDefault("Optimization", "pocs-path", config.POCsPath)
		config.Threads = cf.GetIntDefault("Optimization", "threads", config.Threads)
		config.Quiet = cf.GetBoolDefault("Optimization", "quiet", config.Quiet)
	}

	if cf.HasSection("Account") {
		config.CEyeToken = cf.GetStringDefault("Account", "ceye-token", config.CEyeToken)
		config.SeebugToken = cf.GetStringDefault("Account", "seebug-token", config.SeebugToken)
		config.ZoomEyeToken = cf.GetStringDefault("Account", "zoomeye-token", config.ZoomEyeToken)
		config.ShodanToken = cf.GetStringDefault("Account", "shodan-token", config.ShodanToken)
		config.FofaUser = cf.GetStringDefault("Account", "fofa-user", config.FofaUser)
		config.FofaToken = cf.GetStringDefault("Account", "fofa-token", config.FofaToken)
		config.QuakeToken = cf.GetStringDefault("Account", "quake-token", config.QuakeToken)
		config.HunterToken = cf.GetStringDefault("Account", "hunter-token", config.HunterToken)
		config.CensysUID = cf.GetStringDefault("Account", "censys-uid", config.CensysUID)
		config.CensysSecret = cf.GetStringDefault("Account", "censys-secret", config.CensysSecret)
	}

	if cf.HasSection("Modules") {
		config.Dork = cf.GetStringDefault("Modules", "dork", config.Dork)
		config.MaxPage = cf.GetIntDefault("Modules", "max-page", config.MaxPage)
		config.PageSize = cf.GetIntDefault("Modules", "page-size", config.PageSize)
		config.SearchType = cf.GetStringDefault("Modules", "search-type", config.SearchType)
		config.VulKeyword = cf.GetStringDefault("Modules", "vul-keyword", config.VulKeyword)
		config.SSVID = cf.GetStringDefault("Modules", "ssv-id", config.SSVID)
		config.ConnectBackHost = cf.GetStringDefault("Modules", "lhost", config.ConnectBackHost)
		config.ConnectBackPort = cf.GetStringDefault("Modules", "lport", config.ConnectBackPort)
		config.EnableTLSListener = cf.GetBoolDefault("Modules", "tls", config.EnableTLSListener)
	}

	return nil
}
