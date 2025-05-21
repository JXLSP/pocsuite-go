# 表达式驱动的漏洞检测插件系统

本目录包含了使用表达式驱动的漏洞检测插件示例，类似于长亭科技的x-ray。

## 插件格式

插件使用JSON格式定义，包含以下字段：

```json
{
  "name": "插件名称",
  "version": "版本号",
  "description": "插件描述",
  "author": "作者",
  "references": ["参考资料URL"],
  "tags": ["标签1", "标签2"],
  "severity": "严重程度",  // high, medium, low, info
  "rules": [
    {
      "id": "规则ID",
      "expression": "检测表达式",
      "description": "规则描述"
    }
  ],
  "metadata": {
    "key": "value"
  }
}
```

## 表达式语法

表达式使用[expr-lang/expr](https://github.com/expr-lang/expr)库进行解析和执行，支持以下环境变量和函数：

### 环境变量

- `Request`: HTTP请求对象
  - `Method`: 请求方法
  - `URL`: 请求URL
  - `Headers`: 请求头
  - `Body`: 请求体
- `Response`: HTTP响应对象
  - `StatusCode`: 状态码
  - `Headers`: 响应头
  - `Body`: 响应体
  - `Time`: 响应时间
- `Target`: 目标URL

### 辅助函数

- 字符串处理
  - `contains(s, substr)`: 检查字符串是否包含子串
  - `hasPrefix(s, prefix)`: 检查字符串是否以前缀开始
  - `hasSuffix(s, suffix)`: 检查字符串是否以后缀结束
  - `toLowerCase(s)`: 转换为小写
  - `toUpperCase(s)`: 转换为大写
  - `len(s)`: 获取字符串长度
  - `substr(s, start, end)`: 获取子串
  - `match(pattern, s)`: 模式匹配

- HTTP相关
  - `status()`: 获取响应状态码
  - `body()`: 获取响应体
  - `header(name)`: 获取响应头
  - `responseTime()`: 获取响应时间（毫秒）

## 示例

### SQL注入检测

```json
{
  "id": "error-based-sqli-1",
  "expression": "contains(toLowerCase(body()), 'sql syntax') || contains(toLowerCase(body()), 'mysql error')",
  "description": "检测响应中是否包含SQL错误信息"
}
```

### XSS检测

```json
{
  "id": "reflected-xss-1",
  "expression": "contains(Request.URL, '?name=test') && contains(Response.Body, '<script>test</script>')",
  "description": "检测URL参数是否被直接反射到响应中"
}
```

## 使用方法

```bash
# 使用内置示例插件
./pocsuite3-go expr --target http://example.com

# 使用指定插件文件
./pocsuite3-go expr --plugin-file ./examples/plugins/sql-injection.json --target http://example.com

# 使用插件目录
./pocsuite3-go expr --plugin-dir ./examples/plugins --target http://example.com
```

## 编写自定义插件

1. 创建一个JSON文件，按照上述格式定义插件
2. 使用`expr`命令加载并执行插件

## 与现有POC系统集成

表达式插件系统实现了`Pocser`接口，可以与现有的POC系统无缝集成：

```go
// 创建表达式POC插件
plugin := plugins.ExamplePlugin()
poc := plugins.NewExprPocPlugin(plugin)

// 验证目标是否存在漏洞
result := poc.Verify("http://example.com", nil)
if result {
    fmt.Println("发现漏洞！")
}
```