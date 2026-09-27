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
  - [x] 176j 续:1680-case oracle 已重新给沙箱评分 —— `tests/test_sandbox_fidelity.py`
        **8/8 passed**;parser 臂 scored 1676 / **MISSED 0 / OVER 0** / UNKNOWN 60(3.6%),
        innerHTML 臂 scored 1680 / **MISSED 0 / OVER 0** / UNKNOWN 60。
        即 176j 新纳入的 24 个 corpus_gap 家族**没有暴露任何沙箱误判**。
        注:评分器是**纯 Python 重放**,不启动浏览器,2 秒跑完 1680 行 ——
        oracle 一更新就该跑,没有"太贵"这个借口
  - [ ] 待定(需人决策):JSON 响应里的 reflection 是否连 severity 一起降
        (现在只降 confidence,只按 severity 过滤的下游仍会看到 high)
- [x] **176u 分层记账诚实化(接手未提交 WIP 并修完)**:touch 移到层真实调用之后,
      失败路径落 `status="failed"` 行;测试的 AST 匹配器补上"作为 callable 传给
      `asyncio.to_thread` 的层函数"形态(否则对 async 恒空转)。3/3 passed
- [x] **177 多反射点上下文选择**:两个引擎原来都只按 marker 的第一处反射分类
      (`rank_contexts` 从出生就是零调用),marker 先落惰性上下文(注释/导航高亮)
      后落可执行上下文时,可执行语料永远不会被发。`context.analyze_all()` 按执行
      优先级选主上下文(单反射行为逐字节不变),次上下文候选排队尾不增预算。
      `tests/test_multi_reflection_context.py` 6 例;sync 192 例 f1=1.000 零退化
- [x] **177 续:async 首次与 sync 全量对齐**。FN 漂移分解:so2/scn×4 是 176s 的
      engines 门补上前的旧账(现已 SKIP);其余为环境伪影(隔离复跑全 TP);
      唯一稳定真分歧 neg-filter-05 = async 主循环缺 Phase 166 concat 重试
      (它只存在于需要 WAF 指纹的位置变换分支,无 WAF 的关键字过滤器永远够不着)。
      已补进主循环(escaped 跳过,不破 27-1 收敛预算)。
      **async 192 例 TP108/FP0/TN74/FN0,f1=1.000**(`benchmark_20260925_asyncfix.json`),
      此前最好 0.9455;红队 15/15(阳性现在断言 type/severity/confidence)
- [x] **178b 测试优化六批 + Range3 第三方意见靶场**:敌意输入套件打进交付层与判定层
      (report 8%→83%、param_miner 12%→81%、spa_crawler 8%→45%、poc 9%→73%、
      transform 0→95%),抓到并修复 6 个真缺陷:markdown 单元格注入 + 围栏击穿、
      header 载荷交付 PoC 编码错位、XHR 去重泄漏、**UTF-7 表 4/9 条目编码错误**、
      L8 spy 测试契约过时;async 错误分类学(预算/熔断传播 vs 传输错误降级)首次成测试。
- [x] **178c Range3(range3/)**:SQLite 持久化 + 登录会话 + 混合内容类型的"应用"靶场,
      ground truth 从服务器行为独立撰写,runner 双引擎评分。首轮 sync TP6/FN9 →
      暴露并修复 6 个扫描器缺陷(cookie 单形状、解码回显容器到不了预编码、
      容器检测结构字符过严、JWT 盲注漏已渲染字段、**async 缺 content-type 降置信
      (真 FP)**、async pre-encode payload_survived 错杀 JWT)。终局双引擎零 FP 零 FN
      (sync 16TP, async 14TP + 2 SKIP sync-only)。runner 四条教训固化注释:
      参数须写入起始 URL、连字符路由、stored 标志要全 URL、CLI 解析 -u query
      不做百分号解码。
- [x] **179 决策两项 + 环境两谜案**:JSON 反射 severity 连 confidence 一起降
      (severity-only 消费者不再误判;红队契约更新);变形上下文门控经沙箱
      23×4 实测后**决定不门控**,矩阵落盘 transform.py 设计文档。环境侧查明
      **Windows 保留端口段 8810-9109 吞掉全部惯用端口**(netsh excludedportrange),
      全项目默认端口迁 18xxx 段;三 fixture 服务器启用 HTTP/1.1 keep-alive
      (HTTP/1.0 每请求一条连接 → TIME_WAIT 风暴 → 临时端口耗尽)。遗留:
      test_benchmark 进程内 connect 挂起超 settimeout,见
      dev/WEDGE_test_benchmark_20260927.md。

- [x] **180 Range4 真实框架 SPA 靶场(range4/)**: React 18 `dangerouslySetInnerHTML`
      / Vue 3 `v-html` 对上自动转义的文本节点双胞胎, vendor bundle 是 vendored 进仓库
      的上游发布版。**构造效度先做**: `dev/_r4_construct_probe.py` 在无浏览器前提下证明
      `-safe` 双胞胎的服务端 HTML **不含** attacker 字符串 —— 首版靶场就栽在这里:对照页
      也把参数反射进服务端 JS config line,而那本身是 script-string sink,于是四例全
      confirmed、"safe" 被量成 FP,**错的是靶场不是扫描器**。
      终局**双引擎 8/8 对**(sync / async 各 TP2 FP0 TN2 FN0);runner 现在落盘
      `range4/results.json` 且带门禁语义(FN/FP/ERROR ⇒ exit 1),已挂进 CI 的 tests job。
      顺带挖出的**新缺口**:**async 模式静默忽略 `--headless`** —— AsyncScanner 根本没有
      verify_headless 接线(sync 在 `Scanner._record` 里逐 finding 确认),于是 async 的
      反射型 finding 全是 high/high 却**没有浏览器证据**:本轮 sync 12/12 confirmed,
      async 仅 1/23(且那 1 条是 DOM 层硬编码的 `confirmed=True`)。已先做诚实化:
      `--headless` 进 sync-only 警告列表(两条 async 路径都加)。
- [ ] 待决策:async 要不要补 headless 确认(方案 A 只警告 + 标注 evidence_class;
      方案 B 用 `asyncio.to_thread` 接上,带去重与并发上限)

## 环境配置

- 依赖: requirements.txt;测试: `python tests/run_all_batched.py --quiet`(2026-09-25 实测
  129 个 test_*.py 文件;裸跑单进程会卡死,必须分批 —— `test_async_budget.py` 在本机
  会挂满 2×540s 预算,按"未验证"记账而不是当回归)
- benchmark: benchmark/ 目录;报告产物: report.html
