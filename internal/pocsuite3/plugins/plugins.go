package plugins

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// ExprPlugin 表示基于表达式的漏洞检测插件
type ExprPlugin struct {
	Name        string            `json:"name"`        // 插件名称
	Version     string            `json:"version"`     // 插件版本
	Description string            `json:"description"` // 插件描述
	Author      string            `json:"author"`      // 插件作者
	References  []string          `json:"references"`  // 参考资料
	Tags        []string          `json:"tags"`        // 标签
	Severity    string            `json:"severity"`    // 严重程度: high, medium, low, info
	Rules       []Rule            `json:"rules"`       // 检测规则
	Metadata    map[string]string `json:"metadata"`    // 元数据
}

// Rule 表示检测规则
type Rule struct {
	ID          string `json:"id"`          // 规则ID
	Expression  string `json:"expression"`  // 表达式
	Description string `json:"description"` // 规则描述
}

// HTTPRequest 表示HTTP请求
type HTTPRequest struct {
	Method  string            `json:"method"`  // 请求方法
	URL     string            `json:"url"`     // 请求URL
	Headers map[string]string `json:"headers"` // 请求头
	Body    string            `json:"body"`    // 请求体
}

// HTTPResponse 表示HTTP响应
type HTTPResponse struct {
	StatusCode int               `json:"status_code"` // 状态码
	Headers    map[string]string `json:"headers"`     // 响应头
	Body       string            `json:"body"`        // 响应体
	Time       time.Duration     `json:"time"`        // 响应时间
}

// VulnResult 表示漏洞检测结果
type VulnResult struct {
	Target      string            `json:"target"`      // 目标
	PluginName  string            `json:"plugin_name"` // 插件名称
	VulnName    string            `json:"vuln_name"`   // 漏洞名称
	Severity    string            `json:"severity"`    // 严重程度
	Description string            `json:"description"` // 描述
	Details     map[string]string `json:"details"`     // 详情
	References  []string          `json:"references"`  // 参考资料
	Time        time.Time         `json:"time"`        // 检测时间
}

// ExprEnvironment 表示表达式执行环境
type ExprEnvironment struct {
	Request  HTTPRequest            // HTTP请求
	Response HTTPResponse           // HTTP响应
	Target   string                 // 目标
	Vars     map[string]interface{} // 自定义变量
}

// ExprPluginEngine 表示表达式插件引擎
type ExprPluginEngine struct {
	Plugins     []*ExprPlugin
	Environment *ExprEnvironment
}

// NewExprPluginEngine 创建一个新的表达式插件引擎
func NewExprPluginEngine() *ExprPluginEngine {
	return &ExprPluginEngine{
		Plugins: make([]*ExprPlugin, 0),
		Environment: &ExprEnvironment{
			Vars: make(map[string]interface{}),
		},
	}
}

// LoadPlugin 从文件加载插件
func (e *ExprPluginEngine) LoadPlugin(filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取插件文件失败: %v", err)
	}

	var plugin ExprPlugin
	if err := json.Unmarshal(data, &plugin); err != nil {
		return fmt.Errorf("解析插件文件失败: %v", err)
	}

	// 验证插件格式
	if plugin.Name == "" {
		return errors.New("插件名称不能为空")
	}

	if len(plugin.Rules) == 0 {
		return errors.New("插件必须包含至少一条规则")
	}

	// 预编译表达式以验证语法
	for i, rule := range plugin.Rules {
		_, err := expr.Compile(rule.Expression, expr.Env(ExprEnvironment{}))
		if err != nil {
			return fmt.Errorf("规则 %s 表达式编译失败: %v", rule.ID, err)
		}
		plugin.Rules[i] = rule
	}

	e.Plugins = append(e.Plugins, &plugin)
	return nil
}

// LoadPluginsFromDir 从目录加载所有插件
func (e *ExprPluginEngine) LoadPluginsFromDir(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只处理JSON文件
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
			err := e.LoadPlugin(path)
			if err != nil {
				fmt.Printf("加载插件 %s 失败: %v\n", path, err)
			}
		}

		return nil
	})
}

// SendHTTPRequest 发送HTTP请求并更新环境
func (e *ExprPluginEngine) SendHTTPRequest(req HTTPRequest) (*HTTPResponse, error) {
	// 创建HTTP客户端
	client := &http.Client{}

	// 创建请求
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		return nil, err
	}

	// 设置请求头
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// 发送请求并计时
	startTime := time.Now()
	resp, err := client.Do(httpReq)
	elapsedTime := time.Since(startTime)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 构建响应对象
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	httpResp := &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(body),
		Time:       elapsedTime,
	}

	// 更新环境
	e.Environment.Request = req
	e.Environment.Response = *httpResp

	return httpResp, nil
}

// EvalExpression 评估表达式
func (e *ExprPluginEngine) EvalExpression(expression string) (interface{}, error) {
	// 编译表达式
	program, err := expr.Compile(expression, expr.Env(ExprEnvironment{}))
	if err != nil {
		return nil, fmt.Errorf("表达式编译失败: %v", err)
	}

	// 运行表达式
	result, err := expr.Run(program, e.Environment)
	if err != nil {
		return nil, fmt.Errorf("表达式执行失败: %v", err)
	}

	return result, nil
}

// DetectVulnerability 检测漏洞
func (e *ExprPluginEngine) DetectVulnerability(target string) ([]*VulnResult, error) {
	results := make([]*VulnResult, 0)
	e.Environment.Target = target

	// 遍历所有插件
	for _, plugin := range e.Plugins {
		// 遍历所有规则
		for _, rule := range plugin.Rules {
			// 编译表达式
			program, err := expr.Compile(rule.Expression, expr.Env(ExprEnvironment{}))
			if err != nil {
				fmt.Printf("规则 %s 表达式编译失败: %v\n", rule.ID, err)
				continue
			}

			// 运行表达式
			result, err := vm.Run(program, e.Environment)
			if err != nil {
				fmt.Printf("规则 %s 表达式执行失败: %v\n", rule.ID, err)
				continue
			}

			// 检查结果
			if boolResult, ok := result.(bool); ok && boolResult {
				// 发现漏洞
				vulnResult := &VulnResult{
					Target:      target,
					PluginName:  plugin.Name,
					VulnName:    rule.ID,
					Severity:    plugin.Severity,
					Description: rule.Description,
					Details:     make(map[string]string),
					References:  plugin.References,
					Time:        time.Now(),
				}

				// 添加详情
				vulnResult.Details["request_method"] = e.Environment.Request.Method
				vulnResult.Details["request_url"] = e.Environment.Request.URL
				vulnResult.Details["response_status"] = fmt.Sprintf("%d", e.Environment.Response.StatusCode)

				results = append(results, vulnResult)
			}
		}
	}

	return results, nil
}

// RegisterHelperFunctions 注册辅助函数
func (e *ExprPluginEngine) RegisterHelperFunctions() {
	// 添加常用函数到环境变量中
	e.Environment.Vars["contains"] = strings.Contains
	e.Environment.Vars["hasPrefix"] = strings.HasPrefix
	e.Environment.Vars["hasSuffix"] = strings.HasSuffix
	e.Environment.Vars["toLowerCase"] = strings.ToLower
	e.Environment.Vars["toUpperCase"] = strings.ToUpper
	e.Environment.Vars["len"] = func(s string) int { return len(s) }
	e.Environment.Vars["substr"] = func(s string, start, end int) string {
		if start < 0 || end > len(s) || start > end {
			return ""
		}
		return s[start:end]
	}

	// 正则表达式匹配函数
	e.Environment.Vars["match"] = func(pattern, s string) bool {
		match, _ := filepath.Match(pattern, s)
		return match
	}

	// HTTP相关辅助函数
	e.Environment.Vars["status"] = func() int {
		return e.Environment.Response.StatusCode
	}

	e.Environment.Vars["body"] = func() string {
		return e.Environment.Response.Body
	}

	e.Environment.Vars["header"] = func(name string) string {
		value, ok := e.Environment.Response.Headers[name]
		if !ok {
			return ""
		}
		return value
	}

	e.Environment.Vars["responseTime"] = func() float64 {
		return float64(e.Environment.Response.Time.Milliseconds())
	}
}

// ExamplePlugin 返回一个示例插件定义
func ExamplePlugin() *ExprPlugin {
	return &ExprPlugin{
		Name:        "example-xss-detector",
		Version:     "1.0.0",
		Description: "检测反射型XSS漏洞的示例插件",
		Author:      "pocsuite-go",
		References:  []string{"https://owasp.org/www-community/attacks/xss/"},
		Tags:        []string{"xss", "injection", "web"},
		Severity:    "medium",
		Rules: []Rule{
			{
				ID:          "reflected-xss-1",
				Expression:  "contains(Request.URL, '?name=test') && contains(Response.Body, '<script>test</script>')",
				Description: "检测URL参数是否被直接反射到响应中",
			},
			{
				ID:          "reflected-xss-2",
				Expression:  "status() >= 200 && status() < 300 && contains(body(), Request.Body)",
				Description: "检测请求体内容是否被直接反射到响应中",
			},
		},
		Metadata: map[string]string{
			"impact":     "可能导致用户信息泄露或会话劫持",
			"mitigation": "对所有用户输入进行严格过滤和转义",
		},
	}
}

// 实现与现有POC系统的集成接口
type ExprPocPlugin struct {
	Engine *ExprPluginEngine
	Plugin *ExprPlugin
	Target string
}

// NewExprPocPlugin 创建一个新的表达式POC插件
func NewExprPocPlugin(plugin *ExprPlugin) *ExprPocPlugin {
	engine := NewExprPluginEngine()
	engine.RegisterHelperFunctions()
	engine.Plugins = append(engine.Plugins, plugin)
	return &ExprPocPlugin{
		Engine: engine,
		Plugin: plugin,
	}
}

// Initialize 初始化POC
func (p *ExprPocPlugin) Initialize() error {
	return nil
}

// Verify 验证目标是否存在漏洞
func (p *ExprPocPlugin) Verify(target string, params map[string]any) bool {
	p.Target = target
	p.Engine.Environment.Target = target

	// 构建HTTP请求
	req := HTTPRequest{
		Method: "GET",
		URL:    target,
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		},
	}

	// 从参数中获取自定义设置
	if method, ok := params["method"].(string); ok && method != "" {
		req.Method = method
	}

	if headers, ok := params["headers"].(map[string]string); ok {
		for k, v := range headers {
			req.Headers[k] = v
		}
	}

	if body, ok := params["body"].(string); ok {
		req.Body = body
	}

	// 发送请求
	_, err := p.Engine.SendHTTPRequest(req)
	if err != nil {
		fmt.Printf("发送HTTP请求失败: %v\n", err)
		return false
	}

	// 检测漏洞
	results, err := p.Engine.DetectVulnerability(target)
	if err != nil {
		fmt.Printf("检测漏洞失败: %v\n", err)
		return false
	}

	// 如果有结果，说明存在漏洞
	return len(results) > 0
}

// Attack 利用漏洞进行攻击
func (p *ExprPocPlugin) Attack(target string, params map[string]any) {
	// 在实际场景中，可以根据需要实现攻击逻辑
	fmt.Printf("对目标 %s 执行攻击\n", target)

	// 这里只是简单地调用验证函数
	if p.Verify(target, params) {
		fmt.Println("攻击成功")
	} else {
		fmt.Println("攻击失败")
	}
}

// Cleanup 清理资源
func (p *ExprPocPlugin) Cleanup() error {
	// 清理资源，如关闭连接等
	return nil
}

// GetInfo 获取POC信息
func (p *ExprPocPlugin) GetInfo() map[string]string {
	return map[string]string{
		"name":        p.Plugin.Name,
		"version":     p.Plugin.Version,
		"description": p.Plugin.Description,
		"author":      p.Plugin.Author,
		"severity":    p.Plugin.Severity,
	}
}
