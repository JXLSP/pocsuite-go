package main

import (
	"fmt"
	"os"

	"github.com/seaung/pocsuite-go/internal/pocsuite3/plugins"
)

func main() {
	// 检查命令行参数
	if len(os.Args) < 2 {
		fmt.Println("用法: expr_plugin_demo <目标URL>")
		os.Exit(1)
	}

	target := os.Args[1]
	fmt.Printf("目标: %s\n", target)

	// 创建表达式插件引擎
	engine := plugins.NewExprPluginEngine()
	engine.RegisterHelperFunctions()

	// 加载示例插件
	examplePlugin := plugins.ExamplePlugin()
	engine.Plugins = append(engine.Plugins, examplePlugin)

	// 创建HTTP请求
	req := plugins.HTTPRequest{
		Method: "GET",
		URL:    target,
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		},
	}

	// 发送请求
	fmt.Println("发送HTTP请求...")
	resp, err := engine.SendHTTPRequest(req)
	if err != nil {
		fmt.Printf("发送HTTP请求失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("收到响应: 状态码=%d, 响应大小=%d字节, 响应时间=%v\n",
		resp.StatusCode, len(resp.Body), resp.Time)

	// 检测漏洞
	fmt.Println("开始检测漏洞...")
	results, err := engine.DetectVulnerability(target)
	if err != nil {
		fmt.Printf("检测漏洞失败: %v\n", err)
		os.Exit(1)
	}

	// 输出结果
	if len(results) == 0 {
		fmt.Println("未发现漏洞")
	} else {
		fmt.Printf("发现 %d 个漏洞:\n", len(results))
		for i, result := range results {
			fmt.Printf("[%d] %s (%s)\n", i+1, result.VulnName, result.Severity)
			fmt.Printf("    描述: %s\n", result.Description)
			fmt.Printf("    插件: %s\n", result.PluginName)
			fmt.Printf("    时间: %s\n", result.Time.Format("2006-01-02 15:04:05"))
			fmt.Println("    详情:")
			for k, v := range result.Details {
				fmt.Printf("        %s: %s\n", k, v)
			}
			if len(result.References) > 0 {
				fmt.Println("    参考资料:")
				for _, ref := range result.References {
					fmt.Printf("        - %s\n", ref)
				}
			}
			fmt.Println()
		}
	}

	// 使用与现有POC系统集成的方式
	fmt.Println("\n使用POC接口方式检测漏洞...")
	poc := plugins.NewExprPocPlugin(examplePlugin)
	result := poc.Verify(target, nil)
	if result {
		fmt.Println("POC验证结果: 存在漏洞")

		// 获取POC信息
		info := poc.GetInfo()
		fmt.Println("POC信息:")
		for k, v := range info {
			fmt.Printf("    %s: %s\n", k, v)
		}
	} else {
		fmt.Println("POC验证结果: 不存在漏洞")
	}
}
