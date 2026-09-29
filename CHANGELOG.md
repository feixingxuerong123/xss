# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式;
版本号遵循语义化版本。详细的迭代决策记录见 [AGENTS.md](AGENTS.md)。

## [1.0.0] - 2026-09-29

首个正式版本。以"检测维度最全、架构最干净、最易扩展"为定位的多层级 XSS
检测框架。

### Added

- **双流水线引擎**:sync(线程池)与 async(aiohttp)两条扫描管线,192 例
  精度矩阵双引擎对齐(async f1=1.000,TP108/FP0/FN0)。
- **九层检测体系**:反射探测、WAF 自适应绕过(23+ 变形家族 REGISTRY)、
  DOM 静态污点 + JS AST 数据流、存储型(注入→展示页)、盲打 OOB
  (自托管监听器 / interactsh)、无头浏览器真实执行确认、模板 SSTI、
  框架 DOM sink(React/Vue/Svelte/Lit/Angular)、传输层(CORS / XS-Leaks /
  header / path / cookie / error-page)。
- **上下文感知注入**:20+ 种反射上下文分类,多反射点按执行优先级选主上下文。
- **场景 DSL**:Nuclei 风格声明式多步检测流;CSP nonce 泄露自动利用链。
- **输入面导入**:批量文件/stdin、HAR、OpenAPI/Swagger、Burp/ZAP 原始请求、
  被动代理(--passive,含可选 MITM HTTPS 拦截)。
- **六格式报告**:HTML / JSON / CSV / SARIF 2.1.0 / JUnit / Markdown,外加
  Burp XML 与 nuclei YAML 模板导出(按 finding 真实载体重放)。
- **HTML 报告统一设计系统**(`core/report_theme.py`):明暗双主题、严重度
  筛选/搜索/排序、payload 一键复制、可复现 PoC 目录、截图证据、覆盖率与
  合规映射章节;零外部依赖,离线可开。
- **verify-fix 复测 / diff 基线对比**:CI 友好的 PASS/FAIL 门禁语义。
- **benchmark 套件**:98 / 192 例精度矩阵、分批抗劣化跑法、range3(SQLite
  应用靶场)与 range4(React/Vue 真实框架 SPA 靶场)双引擎评分。
- **API 服务**(`--serve`,flask extra):任务化扫描、指标、通知;LLM 池
  (`--ai-report`)可选增强。
- MIT LICENSE、CONTRIBUTING.md、SECURITY.md。

### Fixed

- 版本号单一源(pyproject dynamic version;SARIF driver 版本不再硬编码)。
- fresh-clone 可复现:`report_theme.py`、`mxss_verify.py` 入库,本地
  git 排除项升入共享 .gitignore。
- CI benchmark-full / nightly-gate 补 `async` extra;esprima 版本下界对齐。
- HTML 报告自身不成为 XSS 载体:载荷全转义、仅 http(s) URL 可点击、
  客户端 JS 零数据插值(测试锁定)。
- markdown 报告的 GFM 表格注入与围栏击穿;UTF-7 语料条目编码错误;
  header 载荷交付 PoC 编码错位;XHR 去重泄漏(详见 AGENTS.md 178b)。

### Security

- LLM provider 密钥移出版本控制,仅保留脱敏模板。
- 全仓库密钥模式扫描通过(仅合成测试键)。
