<!-- agenthub:generated source=.agenthub/PROJECT.md at=2026-08-30T13:12:04.247 hash=ede70d8e1bf1 -->
# xssentinel

## 项目说明

XSS 漏洞自动化扫描器:双流水线架构(scanner Mixin 化 + advanced_layers 域拆分)、场景 DSL(Nuclei 风格声明式多步检测流)、CSP nonce 泄露自动利用链;附 benchmark 跑分与 HTML 报告。

## 规则约定

- scanner.py 已 Mixin 拆分(1101 行核心 + 三 Mixin + findings):新增能力进对应 Mixin,不堆回主文件
- fix_advice.py 数据化(141 行引擎 + JSON 语料):改建议优先改语料
- 多步检测优先写场景 DSL,而非过程式代码

## 任务与进度

- [x] 覆盖率攻坚至 925(report 六格式 + async 深层路径)
- [x] P0 工程质量三件套 + P1 梯队(Playwright 浏览器复用、payload 语料补强)
- [ ] (待补充:当前迭代目标)

## 环境配置

- 依赖: requirements.txt;测试: pytest tests(50+ 测试文件)
- benchmark: benchmark/ 目录;报告产物: report.html
