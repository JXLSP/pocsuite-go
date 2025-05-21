package pocs

// Pocser 定义了POC插件需要实现的接口
type Pocser interface {
	// Initialize 初始化POC，在执行任何操作前调用
	Initialize() error

	// Verify 验证目标是否存在漏洞
	Verify(target string, params map[string]any) bool

	// Attack 利用漏洞进行攻击
	Attack(target string, params map[string]any)

	// Cleanup 清理POC执行过程中产生的资源
	Cleanup() error

	// GetInfo 获取POC的基本信息
	GetInfo() map[string]string
}
