<!-- agenthub:generated source=.agenthub/PROJECT.md at=2026-08-30T13:12:04.248 hash=ede70d8e1bf1 -->
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
- [ ] **当前迭代目标:让判定有测量支撑,而不是让基准更好看(Phase 176f–176r)**
  - [x] 176f 补齐最后一个未覆盖层 → 50/50:`*.localhost` 解析到 loopback,
        可造出真实父子域对(L8_cookie_tossing),无需 DNS
  - [x] 176g 独立靶场红队验证(召回 9/9、诱饵 5/5 沉默);顺带补上从未被
        任何用例执行过的 content-type 分支(**层覆盖 ≠ 分支覆盖**)
  - [x] 176h 把独立靶场固化成常驻回归 `tests/test_redteam_independent.py`,
        每轮门禁都跑,不再依赖"手气好的时候手动跑一次"
  - [x] 176i 用 Chromium 全量 oracle(60×20=1200 cases)给纯 Python 沙箱重新打分,
        修掉 MISSED/OVER —— 结果 `tests/test_sandbox_fidelity.py` **8/8 passed,
        MISSED 0 / OVER 0**。唯一分歧(mxss-body-br × iframe_src)经**对照重跑**
        证明是 iframe settle 等待不足(300ms→1500ms),**沙箱一直是对的**
  - [x] 176j oracle 重采:矩阵 60×20=1200 → **84×20=1680**,补进 corpus_gap 指出的
        24 个语料家族各一条代表载荷(只把 alert(1) 换成 sentinel),
        产物 `benchmark/results/browser_dom_oracle.json`
  - [ ] **176j 续:1680-case oracle 扩完之后尚未重新给沙箱评分**(重采落盘了,
        评分没跑)。收口动作 = 重跑 `tests/test_sandbox_fidelity.py`,
        要求 MISSED=0 且 OVER=0 —— MISSED 优先,那是"浏览器会执行而沙箱判惰性",
        即永不报告的漏洞
  - [ ] 待定(需人决策):JSON 响应里的 reflection 是否连 severity 一起降
        (现在只降 confidence,只按 severity 过滤的下游仍会看到 high)

## 环境配置

- 依赖: requirements.txt;测试: `python tests/run_all_batched.py --quiet`(2026-09-25 实测
  129 个 test_*.py 文件;裸跑单进程会卡死,必须分批 —— `test_async_budget.py` 在本机
  会挂满 2×540s 预算,按"未验证"记账而不是当回归)
- benchmark: benchmark/ 目录;报告产物: report.html
