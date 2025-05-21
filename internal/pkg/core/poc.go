package core

import (
	"fmt"
	"strings"
	"time"
)

type BasePoc struct {
	VulnID     string
	Version    string
	Author     string
	VulnDate   string
	CreateDate string
	UpdateDAte string
	VulnType   string
	Desc       string
	References string
}

// ValidateFields 验证POC的必要字段
func (b *BasePoc) ValidateFields() error {
	if b.VulnID == "" {
		return fmt.Errorf("漏洞ID不能为空")
	}
	if b.Version == "" {
		return fmt.Errorf("POC版本不能为空")
	}
	if b.Author == "" {
		return fmt.Errorf("作者信息不能为空")
	}
	if b.VulnType == "" {
		return fmt.Errorf("漏洞类型不能为空")
	}
	if b.Desc == "" {
		return fmt.Errorf("漏洞描述不能为空")
	}
	return nil
}

// PrintPocInfo 打印POC的详细信息
func (b *BasePoc) PrintPocInfo() {
	fmt.Printf("漏洞ID: %s\n", b.VulnID)
	fmt.Printf("POC版本: %s\n", b.Version)
	fmt.Printf("作者: %s\n", b.Author)
	fmt.Printf("漏洞发现日期: %s\n", b.formatDate(b.VulnDate))
	fmt.Printf("POC创建日期: %s\n", b.formatDate(b.CreateDate))
	fmt.Printf("POC更新日期: %s\n", b.formatDate(b.UpdateDAte))
	fmt.Printf("漏洞类型: %s\n", b.VulnType)
	fmt.Printf("漏洞描述:\n%s\n", b.formatDesc())
	if b.References != "" {
		fmt.Printf("参考链接:\n%s\n", b.formatReferences())
	}
}

// formatDate 格式化日期字符串
func (b *BasePoc) formatDate(date string) string {
	if date == "" {
		return "未知"
	}
	// 尝试解析日期字符串
	_, err := time.Parse("2006-01-02", date)
	if err != nil {
		return date // 如果解析失败，返回原始字符串
	}
	return date
}

// formatDesc 格式化漏洞描述
func (b *BasePoc) formatDesc() string {
	return strings.TrimSpace(b.Desc)
}

// formatReferences 格式化参考链接
func (b *BasePoc) formatReferences() string {
	refs := strings.Split(b.References, ",")
	var formattedRefs []string
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref != "" {
			formattedRefs = append(formattedRefs, fmt.Sprintf("- %s", ref))
		}
	}
	return strings.Join(formattedRefs, "\n")
}
