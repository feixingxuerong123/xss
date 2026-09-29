# 安全政策

## 授权使用

XSSentinel 是一款授权测试专用的 XSS 漏洞自动化扫描工具。**只对你拥有或获得
书面授权的系统使用它。** 未经授权对他人系统进行扫描/攻击在大多数司法辖区
属于违法行为;本工具的产出(含 PoC、payload 语料)也应按敏感数据处理。

## 报告 XSSentinel 自身的漏洞

如果你在 XSSentinel 本身(扫描器、报告生成、API 服务、导出器)发现安全
问题,请不要公开 issue,优先走私密渠道:

1. **GitHub 私密安全通告**(推荐):仓库 → Security → Report a vulnerability。
2. 或联系维护者(联系方式待补充——仓库归属者请在此处填入邮箱/表单)。

请在报告中包含:受影响模块、复现步骤(最小输入优先)、影响评估。我们会在
72 小时内确认收到,修复发布前对你致谢(除非你要求匿名)。

**特别关注的攻击面**(这个工具的特殊性决定):

- **报告生成路径**:finding 字段(url / param / payload / detail / 证据截取)
  全部来自被扫目标的响应——报告 HTML / Markdown / SARIF / XML 不应被恶意
  目标反向变成攻击载体。历史修复参考 `tests/test_p23.py`、
  `test_report_formats.py` 的敌意输入用例;新报告格式/字段必须同样通过
  转义契约测试。
- **靶场与自测服务器**(`range3/`、`range4/`、`--self-test`、`--sandbox`)
  刻意包含真实可执行漏洞,**只绑定 loopback**,请勿改成对外监听。
- **OOB 监听器与被动代理**的端口、TLS 证书(`--mitm-ca`)落在本地磁盘,
  报告泄露即可被冒用。

## 密钥与敏感配置

- LLM provider 密钥只放 `xssentinel/data/llm_providers.json`(已被
  .gitignore 忽略);模板见 `llm_providers.example.json`。
- 疑似泄露:立即轮换密钥;历史提交中的密钥视为已泄露,需在服务商侧吊销。

## 支持版本

仅最新 main 分支接收安全修复;发布 tag 请以 CHANGELOG 为准。
