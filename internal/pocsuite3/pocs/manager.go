package pocs

import (
	"fmt"
	"sync"
)

// PocManager 管理POC插件的注册和获取
type PocManager struct {
	pocs map[string]Pocser
	mux  sync.RWMutex
}

// NewPocManager 创建一个新的POC管理器
func NewPocManager() *PocManager {
	return &PocManager{
		pocs: make(map[string]Pocser),
	}
}

// RegisterPoc 注册一个POC插件
func (pm *PocManager) RegisterPoc(poc Pocser) error {
	// 初始化POC
	if err := poc.Initialize(); err != nil {
		return fmt.Errorf("初始化POC失败: %v", err)
	}

	// 获取POC信息
	info := poc.GetInfo()
	vulnID := info["vulnID"]
	if vulnID == "" {
		return fmt.Errorf("POC的漏洞ID不能为空")
	}

	// 注册POC
	pm.mux.Lock()
	defer pm.mux.Unlock()

	if _, exists := pm.pocs[vulnID]; exists {
		return fmt.Errorf("POC %s 已经注册", vulnID)
	}

	pm.pocs[vulnID] = poc
	return nil
}

// GetPoc 根据漏洞ID获取POC
func (pm *PocManager) GetPoc(vulnID string) (Pocser, error) {
	pm.mux.RLock()
	defer pm.mux.RUnlock()

	poc, exists := pm.pocs[vulnID]
	if !exists {
		return nil, fmt.Errorf("POC %s 不存在", vulnID)
	}

	return poc, nil
}

// ListPocs 列出所有已注册的POC
func (pm *PocManager) ListPocs() []map[string]string {
	pm.mux.RLock()
	defer pm.mux.RUnlock()

	var pocList []map[string]string
	for _, poc := range pm.pocs {
		pocList = append(pocList, poc.GetInfo())
	}

	return pocList
}

// UnregisterPoc 注销一个POC
func (pm *PocManager) UnregisterPoc(vulnID string) error {
	pm.mux.Lock()
	defer pm.mux.Unlock()

	poc, exists := pm.pocs[vulnID]
	if !exists {
		return fmt.Errorf("POC %s 不存在", vulnID)
	}

	// 清理POC资源
	if err := poc.Cleanup(); err != nil {
		return fmt.Errorf("清理POC资源失败: %v", err)
	}

	delete(pm.pocs, vulnID)
	return nil
}