package cmdoptions

import (
	"fmt"
	"os"

	"github.com/seaung/pocsuite-go/internal/pocsuite3/plugins"
	"github.com/spf13/cobra"
)

var (
	pluginDir  string
	pluginFile string
	target     string
)

var exprCmd = &cobra.Command{
	Use:   "expr",
	Short: "使用表达式驱动的漏洞检测插件",
	Long:  "使用表达式驱动的漏洞检测插件，类似于长亭科技的x-ray",
	Run: func(cmd *cobra.Command, args []string) {
		// 创建插件引擎
		engine := plugins.NewExprPluginEngine()
		engine.RegisterHelperFunctions()

		// 加载插件
		if pluginDir != "" {
			fmt.Printf("从目录 %s 加载插件\n", pluginDir)
			err := engine.LoadPluginsFromDir(pluginDir)
			if err != nil {
				fmt.Printf("加载插件目录失败: %v\n", err)
				os.Exit(1)
			}
		} else if pluginFile != "" {
			fmt.Printf("加载插件文件 %s\n", pluginFile)
			err := engine.LoadPlugin(pluginFile)
			if err != nil {
				fmt.Printf("加载插件文件失败: %v\n", err)
				os.Exit(1)
			}
		} else {
			// 使用示例插件
			fmt.Println("未指定插件，使用内置示例插件")
			examplePlugin := plugins.ExamplePlugin()
			engine.Plugins = append(engine.Plugins, examplePlugin)
		}

		// 检查是否有插件加载
		if len(engine.Plugins) == 0 {
			fmt.Println("没有加载任何插件")
			os.Exit(1)
		}

		fmt.Printf("已加载 %d 个插件\n", len(engine.Plugins))
		for i, plugin := range engine.Plugins {
			fmt.Printf("[%d] %s - %s (作者: %s)\n", i+1, plugin.Name, plugin.Description, plugin.Author)
		}

		// 检查目标
		if target == "" {
			fmt.Println("未指定目标，请使用 --target 参数指定目标")
			os.Exit(1)
		}

		// 构建HTTP请求
		req := plugins.HTTPRequest{
			Method: "GET",
			URL:    target,
			Headers: map[string]string{
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			},
		}

		// 发送请求
		fmt.Printf("发送请求到目标: %s\n", target)
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
	},
}

func init() {
	exprCmd.Flags().StringVar(&pluginDir, "plugin-dir", "", "插件目录路径")
	exprCmd.Flags().StringVar(&pluginFile, "plugin-file", "", "插件文件路径")
	exprCmd.Flags().StringVar(&target, "target", "", "目标URL")

	// 添加到根命令
	rootCmd.AddCommand(exprCmd)
}
