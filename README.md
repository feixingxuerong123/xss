# XSSentinel — 综合型 XSS 检测框架

> 一款**多层级、可扩展**的 XSS 检测工具：反射点上下文感知注入 + WAF 自适应绕过 + DOM 污点分析 +（可选）无头浏览器真实验证。

---

## ⚠️ 定位与诚实声明（请先读）

市面上成熟的商业工具（如 Acunetix、Burp Suite Pro、Netsparker）由大型团队长期维护，覆盖大量私有规则与爬虫能力。**没有任何一款开源工具能"全面超过"它们**——这是个移动靶。

XSSentinel 的目标是**在开源/自研工具中做到检测维度最全、架构最干净、最易扩展**：它把通常被单点工具割裂的能力整合进一个流水线，并且每一层都可单独替换/增强。它在以下方面优于常见的单技术 XSS 脚本：

- **6 层检测流水线**：反射 → WAF 绕过 → DOM 污点 → 存储型 → 盲打(OOB) → 无头确认，覆盖大多数工具只做其中 1–2 项的盲区。
- **上下文感知**：先判断输入反射在 HTML 元素 / 属性 / 脚本字符串 / 事件处理器 / `javascript:` URI / SVG / MathML / CDATA / 模板 `{{}}` / meta-refresh / HTML 注释等 **20+ 种上下文**，再选对应 payload。
- **反射画像驱动（Phase 31）**：反射确认后自动发一枚"三明治探针"（DalFox 式），识别哪些特殊字符被过滤/编码，按需把最可能命中的 payload 与 WAF 绕过变形排到队首（ZAP 式字符反馈闭环），预算利用率更高——benchmark 上同等精度下总耗时下降约 10%。
- **生成式 payload（Phase 32）**：不只检索语料，还按反射画像用**仅存活的字符**现场构造 payload（XSStrike 思路）；括号被过滤时自动切换为无括号的 tagged-template 调用 `alert\`1\``，能穿过拦住语料 payload 的过滤器。
- **签名级端点去重 + 内容类型降置信（Phase 32）**：爬虫产物按 `方法+主机+路径+参数名集合` 去重，分页/重复参数的端点不重复扫（DalFox 思路）；JSON/纯文本响应中的反射命中自动降为 low confidence（ZAP 思路），让人优先看真正的 HTML 汇聚点。
- **参数位置变换（Phase 33）**：WAF 常只守参数的原始位置——标准位置全部未确认且检测到 WAF 时，自动把 top payload 克隆到另一位置（query↔body）重发（Burp 思路），固定小预算不膨胀请求量。
- **审计优先级 + 策略预设（Phase 33）**：并发队列按攻击面价值排序（参数数 / POST / admin·comment 等敏感路径优先，Burp 思路）；`--scan-policy {quick,normal,deep}` 一键切换预算档位（ZAP Threshold/Strength 思路），显式 flag 始终覆盖预设。
- **自动预编码管道（Phase 34）**：自动识别 base64 / 双重 base64 / JSON-in-base64 / JWT 容器参数，把 payload 用**同样的容器重新包装**后注入（DalFox 思路）——JWT 保留 header 与签名段、JSON 追加字段；命中即跳过对结构化参数几乎无望的明文 payload 循环。
- **CSP 感知预算门控（Phase 35）**：strict CSP（内联被禁且分析器未发现绕过路径）时自动把反射 payload 预算切到早停档，nonce 策略保守放行（可能存在 nonce 泄露绕过）；可绕过的 CSP 保持全预算。`--async` 高吞吐模式同步接入预编码管道（Phase 43 修复：async 主入口的 `as_completed(async_generator)` 误用与 scan-policy 预设填充缺失均已修复，`--async` 单目标/批量现已端到端可用并有真实 HTTP 回归测试守护）。
- **验证器 RCDATA 加固（Phase 35）**：lxml 的 HTML 结构修复会把写在 `<title>/<textarea>/<xmp>` 内的标签提升到文档顶层、丢失 RCDATA 祖先——语义验证器现在在结构化解析**之前**先做原始文本 RCDATA 检查，杜绝该类罕见误报；真正的 `</title>` 后逃逸仍然照常确认。
- **WAF 自适应绕过**：检测到拦截后，自动套用 **23 种**变形/编码家族（混合大小写、HTML/JS/CSS/UTF-7 实体、注释打断、空字节、全角、构造器逃逸、重复属性等）生成绕过变体；数量以 `core/transform.py` 的 `REGISTRY` 为准，新增变形只改 REGISTRY 即可。
- **DOM XSS 静态污点分析**：不依赖服务器响应，直接分析前端 JS 的 source→sink 流（如 `location.hash` → `innerHTML`、jQuery `.html()`、`postMessage` 事件、`dangerouslySetInnerHTML`、`v-html`、`{{ }}` 等）。
- **JS AST 数据流分析（Phase 43）**：esprima ESTree 解析每个 `<script>` 块，跟踪污点变量跨声明/赋值/拼接的多跳传播（含压缩混淆代码与 postMessage 回调函数体），产出带 `[AST]` 标记的高置信 source→sink 链（DalFox v3 式）；解析失败透明回退正则通道（`pip install xssentinel[ast]` 启用，缺失时自动降级）。
- **DOM XSS 真·浏览器执行确认（L6 强化）**：在真实无头浏览器（Playwright）里给危险 sink 插桩——`innerHTML`/`outerHTML`/`document.write`/`Function`/`setTimeout`/`location.*`/`window.open`/`setAttribute(on*)`/jQuery `.html()` 等，并把唯一标记注入 `location.hash`/`location.search`/`document.cookie`/`postMessage` 等可控源。**标记一旦真正流入 sink，即判定为已确认（high）DOM XSS**——这是猜测式静态分析无法给出的硬证据（静态命中仅作为 medium/low 提示）。Playwright 不可用时优雅降级为静态启发式，不影响其他层。
- **存储型 XSS**：注入后重新拉取"展示页"确认持久化执行（多数开源工具不做）。
- **盲打 XSS（OOB）自动确认**：注入带唯一 token 的带外回调 payload，再轮询回调监听服务——**收到 beacon 即判定为已确认（high）盲打**，而非只"撒网不收网"。支持自托管监听器（`--oob self`，离线可测）与公共 interactsh（`--oob interactsh`，真实场景）。
- **双重确认**：语义确认（token 是否落在真实可执行汇聚点，且用 BeautifulSoup 结构化判定，可识别 `html.escape` 伪漏洞）+ 可选无头浏览器真实弹窗确认，显著降低误报。
- **深度爬虫**：`-c` 自动发现同域 `<a>` 链接与 `<form>` 端点（BFS，`--crawl-depth` 控深度，`--scope` 限域），连"无参数纯 DOM 页面"也纳入扫描——多数单脚本工具跑完一个 URL 就停了。
- **发现去重**：`dedup()` 按 `(type, URL, param, context)` 合并经不同爬取路径/变形变体发现的同一漏洞，避免重复告警刷屏（DOM 类忽略 query 差异）。
- **隐藏参数挖掘（Phase 43）**：内置 313 个高产出候选词（分页/token/回跳/模板等 14 类），`--param-wordlist` 可追加自定义词表（操作符提示前置）；fuzzer 差分 triage 从大词表挑 top-N 深测，请求量可控。
- **双引擎精度对齐（Phase 43）**：`benchmark/runner.py --engine {sync,async}` 用同一 98 用例矩阵分别标定两条流水线——async 经 CSP 响应头门、转义实体窗口、mXSS payload 自带结构守卫三层修复后已达 **recall 100% / precision 100% / FPR 0**，与 sync 完全对齐（Phase 69 重新标定：sync 98 用例 TP=64/FP=0/FN=0，recall/precision 100%，FPR 0——此前本机退化 loopback 曾出现 1 例环境性假 FN，单跑该用例 0.2s 即检出；runner 现对出错用例自动重试，且**漏洞用例若最终无法完成计入 FN**，不再让跑不完的用例悄悄缩小 recall 分母）。**注意该标定已被 Phase 91/92 刷新**：当时 async 基线里 3 个 safe 用例存在从未暴露的误报（Phase 84 引入），最新数字见文末「当前基线」表——precision 仍是 1.000，但 recall 分母口径下的 FN 需先单跑复现再判定。
- **可复现 PoC**：每个确认漏洞自动产出 **curl 命令 + 含 payload 的 URL + 自包含 HTML PoC 页面**（iframe / 自动提交表单 / `location.hash` 触发 DOM），HTML/JSON/CSV/SARIF 四报告均携带，直接交差或进缺陷单。
- **被动代理扫描（Phase 44）**：`--passive` 起本地 HTTP 代理（对标 xray / w13scan 的被动模式），浏览器/工具挂代理即可把流量捕获进扫描流水线——按 `方法+主机+路径+参数名集合` 签名去重（分页/翻 token 不重扫），GET/POST 表单与 JSON body 全解析，HTTPS 默认走 CONNECT 隧道透传；加 `--mitm-ca ca.pem`（Phase 50）则自动生成本地 CA 并对 scope 内主机做 HTTPS 拦截——每主机证书由该 CA 签发，把 CA 证书 `ca-cert.pem` 装进浏览器/系统信任库后 HTTPS 参数/body 也能被捕获扫描（越 scope 主机保持盲透传）；后台 worker 把捕获端点直接喂给 L1 流水线，`--sqli-check` / `--check-outdated-js` 快检可联动（见下）。写端点（POST/PUT/PATCH）扫描后自动进入 **stored 二阶观察**：对 body 参数注入唯一 token 探针，之后浏览到的任意页面若原样渲染该 token（可执行上下文）即确认 high `second_order` finding——存储型 XSS 无需手动指定注入/查看端点（Phase 67）。
- **目标级 CORS / XS-Leaks 审计（Phase 51/53）**：每 origin 探测 Origin 反射（GET+OPTIONS 兜底）——反射任意 Origin+Allow-Credentials → high `cors_misconfig`；`--audit-xs-leaks` 对无任何跨源隔离头（COOP/CORP/COEP/帧守卫）的页面记 low `xs_leak_surface`；`xs_leaks.py` 另附 img/frame-timing/window.name/history 四信道载荷库与免服务器演示 PoC（证明已确认 XSS 的跨站窃取半径）。sync/async 双引擎对齐（Phase 54）。
- **生态导出保真（Phase 55）**：nuclei 导出按 finding 真实载体重放——query 反射走参数、上传走 multipart raw、`(header:X)`/`(cookie:X)` 走 raw 请求头/Cookie、path/error 走百分号编码路径（均有 nuclei live-MATCH 回归测试）；Burp XML 内嵌可复现请求。
- **SQLi 错误回显快检（Phase 44）**：`--sqli-check` 对标 dalfox grep 引擎 / xray sqldet——向每个参数注入 7 枚引号类探针，用 MySQL / PostgreSQL / MSSQL / Oracle / SQLite 五家族指纹正则匹配数据库错误回显（无回显不报），命中即报 finding 并停止该参数，先做 baseline 跳过本身就带 DB 错误的页面。
- **过时 JS 库扫描（Phase 44）**：`--check-outdated-js` 对标 XSStrike retireJS——解析 `<script src>`，版本提取锚定库名（`/static/v2/jquery.min.js` 的 v2 不误判为 jQuery 版本），比对 jQuery / AngularJS / Bootstrap / Vue / Underscore / Lodash / Handlebars 七库的已知 CVE 版本区间，命中即报 outdated_js_lib（medium/high）。
- **镜像页防护（Phase 78）**：param_miner 哨兵预探测（3 个随机哨兵全反射=镜像页，3 请求替代 100 候选洪水）+ 滚动反射比熔断（近 15 次 ≥85% 反射即 collapse，保留 1 个"任意参数"代表项）——吸收自 DalFox 2025 发现管线。
- **FUZZ 任意位置注入（Phase 79/80）**：`--fuzz-body '{"filter": FUZZ}' --fuzz-marker FUZZ` —— body 模板内任意位置（JWT 内层/XML 节点/深层 JSON 叶子）的标记全量替换注入，反射（raw/URL 编码）与确认（verbatim 未转义 + 危险形状）分级报告；`--fuzz-body @file` 支持模板文件。吸收自 DalFox FUZZ 模式。
- **BAV 联动探针（Phase 81/82）**：`--bav` —— 隐藏参数挖掘命中的参数顺带做三类相邻漏洞探测：SSTI（{{777*'7'}}→5439 唯一常数）、CRLF（注入响应头回显）、开放重定向（3xx Location 指向唯一 host），各一请求、无模糊启发式；确认项入报告（type `bav`）。吸收自 DalFox BAV 分析。
- **原始请求文件输入（Phase 83）**：`--raw-request captured.txt` —— Burp/ZAP "copy as raw" 格式直接作为扫描入口：方法/URL（Host 构造）/头/Cookie/body 全部回填后走完整扫描管线（认证/OOB/爬取/报告继承），无平行弱实现。对齐 DalFox `--rawdata`。
- **批量输入管道（Phase 87 P0）**：`--batch urls.txt` 与 `--batch-stdin`（管道流式喂入，一行一个 URL，# 注释）——侦察链（httpx/gau/wayback）输出可直接接进扫描器，URL 去重、失败目标不中断整批、按目标分报告。对齐 DalFox pipe 模式。
- **HAR 导入（Phase 88 P1）**：`--har capture.har` —— 浏览器 DevTools/Burp/ZAP 导出的 HTTP Archive 直接作为扫描入口：每个捕获请求展开为一个真实端点，method/form·JSON body/cookie/自定义头全部回填后走完整扫描管线（对齐 Burp/XSpear 的 HAR 入口）。
- **OpenAPI/Swagger 导入（Phase 89 P1）**：`--openapi spec.json` —— 文档化的 API 契约（OpenAPI 3.x / Swagger 2.0）直接作为扫描入口：每个 path+operation 展开为端点（含浏览器从未访问过的路由），路径模板 `{id}` 按 example/schema 链解析为样本 URL，form/JSON body 由 schema 构建，apiKey/bearer 安全声明转为请求头。与 HAR 互补：HAR 覆盖"实际流量"，OpenAPI 覆盖"声明面"。
- **抗劣化分批基准跑（Phase 44，Phase 91 扩参）**：`benchmark/run_benchmark_batched.py [out.json] [batch] [port] [sync|async] [max_payloads] [max_transforms] [timeout]` —— `run_benchmark.py` 在单进程内跑完 98 用例，遇到会间歇掐 loopback 的安全软件（WinError 10053/10054）时必然卡在中途（实测 7 次 0 完成）；分批版按小批（默认 6）评估、**每批落盘**、支持中断续跑与失败重试。位置参数 4-7 可选（默认 sync/10/6/45），传 `sync 14 12 90` 即复现标定口径；续跑时预算变了会丢弃旧结果。**Windows 本机跑完整矩阵请用这个入口**（默认预算 6–7 分钟全矩阵，14/12/90 口径 sync 约 12 分钟、async 约 25 分钟）。
- **多格式报告 + 并发**：HTML / JSON / CSV / **SARIF(2.1.0) / JUnit / Markdown** 六格式，SARIF 可直接接入 CI / 缺陷平台（如 GitHub code scanning、Defender、Jira）；多线程端点/参数并发扫描。

**只用于你被授权测试的系统。**

---

## 检测架构（6 层）

```
L1  反射层    探针定位反射点 → 上下文分析(20+ 种) → 按上下文选 payload 并发射
L2  WAF 绕过   命中拦截 → 套用 23 种变形/编码家族生成变体 → 再尝试
L3  DOM 层     静态分析页面 JS：source( location/document/postMessage… ) → sink( innerHTML/eval/jQuery… )
L4  存储层     注入 → 重新拉取"展示页" → 确认持久化执行
L5  盲打层     (可选)为每处注入生成唯一 token 的 OOB payload → 轮询回调监听 → 收到 beacon 即"已确认"盲打
L6  无头/DOM   (可选)Playwright 真实渲染：① 对 DOM sink 插桩并注入唯一标记，标记流入 sink 即"已确认"DOM XSS；
        动态确认   ② 捕获 dialog 事件作为反射型铁证
        │
        └─ 每层结果都经过"语义确认"：注入唯一 token，确认它落在真实可执行位置
           而非仅被原样回显（可有效识别 html.escape 后的伪漏洞）

发现层（串联上述检测层）：
  • 深度爬虫  -c（BFS，--crawl-depth 控制深度，--scope 限域）：自动发现同域
             <a> 链接与 <form> 端点，连无参数的纯 DOM 页面也纳入扫描。
  • 去重      dedup()：按 (type, URL, param, context) 合并多路径/多变形发现的同一
             漏洞，避免重复告警（DOM 类忽略 query 差异）。
  • 可复现 PoC - 每个确认漏洞自动生成 curl 命令、含 payload 的 URL、以及自包含
             HTML PoC 页面（iframe / 自动提交表单 / location.hash 触发 DOM），
             直接交给同事或写进报告。
```

---

## 安装

```bash
cd xssentinel
python -m venv .venv && .venv\Scripts\activate     # Windows
#   或：source .venv/bin/activate                  # Linux/macOS
pip install -e .                                   # 依赖：requests, beautifulsoup4
```

可选（用于 L4 无头浏览器确认）：
```bash
pip install playwright && playwright install chromium
```

---

## 快速使用

### 命令行

```bash
# 扫描单个 GET 参数（自动从 URL ?q= 提取）
python -m xssentinel -u "https://example.com/search?q=test" -o report.html

# POST 表单
python -m xssentinel -u "https://example.com/comment" -m POST -d "name=x&bio=y"

# 带认证 / 代理
python -m xssentinel -u "https://example.com/p" -H "Authorization: Bearer XXX" -b "session=yyy"

# 表单登录（认证感知爬取）：登录成功后 cookie/token 自动携带，会话丢失自动重登
python -m xssentinel -u "https://example.com/app" -c \
  --login-url "https://example.com/login" --login-user user --login-pass pass \
  --login-field-user username --login-field-pass password \
  --login-success-marker "dashboard" --auth-relogin-on-loss

# 断点续扫：大站中断后从检查点继续（已扫端点不重扫）
python -m xssentinel -u "https://example.com" -c --checkpoint cp.json
python -m xssentinel -u "https://example.com" -c --checkpoint cp.json --resume

# 爬取表单与链接后逐个扫描（默认深度 2）
python -m xssentinel -u "https://example.com" -c

# 深度爬虫：加大深度 + 限定 scope 前缀（只爬该路径下的同域页面）
python -m xssentinel -u "https://example.com/app" -c --crawl-depth 3 --scope "https://example.com/app"

# 深度爬虫会去重并自动为每个确认漏洞生成可复现 PoC（见报告 PoC 列）

# 真·浏览器确认（需 playwright）
python -m xssentinel -u "https://example.com/search?q=test" --headless

# DOM-XSS 引擎选择（默认 auto：装了 playwright 就用真浏览器确认，否则退化为静态启发式）
python -m xssentinel -u "https://example.com/search?q=test" --dom-engine auto
# 强制使用真浏览器（未装 playwright 会优雅降级，仍给出静态结论）
python -m xssentinel -u "https://example.com/search?q=test" --dom-engine playwright
# 仅用静态启发式（不启动浏览器，最快）
python -m xssentinel -u "https://example.com/search?q=test" --dom-engine static

# 六种报告（-f 支持 html,json,csv,sarif,junit,markdown）
python -m xssentinel -u "https://example.com/search?q=test" -f json -o report.json
python -m xssentinel -u "https://example.com/search?q=test" -f sarif -o report.sarif

# 存储型 XSS（注入 /store，再拉取 /view 确认）
python -m xssentinel -u "https://example.com/p" --stored-inject https://example.com/store --stored-view https://example.com/view

# 盲打 XSS 自动确认（自托管监听器，离线/测试用，收到 beacon 即确认）
python -m xssentinel -u "https://example.com/search?q=test" --oob self

# 盲打 XSS 自动确认（公共 interactsh 服务器，真实场景）
python -m xssentinel -u "https://example.com/search?q=test" --oob interactsh

# 并发扫描（4 线程）
python -m xssentinel -u "https://example.com/search?q=test" --threads 4

# 声明式多步场景（存储流等；JSON 配置，Nuclei 风格）
python -m xssentinel -u "https://example.com/comment" --scenarios my_scenarios.json

# 被动代理扫描：浏览器/工具挂本代理，流量自动进扫描流水线（对标 xray/w13scan）
python -m xssentinel --passive --proxy-port 8080 --sqli-check --check-outdated-js
#   浏览器设置 HTTP 代理 http://127.0.0.1:8080 即可；HTTPS 默认 CONNECT 隧道透传
#   --mitm-ca mitm/ca.pem 开启 HTTPS 拦截（自动生成 CA）；先装 mitm/ca-cert.pem 到信任库
#   捕获端点按 方法+主机+路径+参数名集合 去重，Ctrl+C 退出并写出报告
#   multipart 上传请求的文件字段会被自动识别并路由到上传 filename XSS 探针

# 上传 filename XSS（sync 与 --async 通用；--upload-field 可重复给出多个字段）
python -m xssentinel -u "https://example.com/up" -m POST --upload-field file

# SQLi 错误回显快检（对标 dalfox grep 引擎，独立模式）
python -m xssentinel -u "https://example.com/search?q=1" --sqli-check

# 过时 JS 库扫描（对标 XSStrike retireJS）
python -m xssentinel -u "https://example.com" --check-outdated-js
```

常用参数：`-m/--method`、`-d/--data`、`-c/--crawl`、`--headless`、`--timeout`、
`--scan-policy {quick,normal,deep}`（策略预设，显式 flag 覆盖预设；max-transforms / max-payloads / threads 的默认值由预设档位决定——normal 档为 12 / 10 / 4，quick 档更低，显式传参始终优先）、
`--max-transforms`（绕过变体数，随预设档位）、`--max-payloads`（每上下文最大 payload 数，随预设档位）、
`--threads`（并发线程数，随预设档位）、`--oob {self,interactsh}`（盲打自动确认模式）、
`--oob-timeout`（等待回调秒数，默认 12）、
`--dom-engine {auto,playwright,static}`（DOM-XSS 引擎：auto=有 playwright 用真浏览器确认、否则静态；playwright=强制真浏览器；static=仅静态启发式，默认 auto）、
`--stored-inject` / `--stored-view` / `--stored-param`（存储型扫描）、
`-o/--output`、`-f/--format {html,json,csv,sarif,junit,markdown,burp,nuclei}`（burp=Burp XML、nuclei=每 finding 一个可运行模板目录）、
`--upload-field`（上传 filename XSS，见上）、
`--audit-xs-leaks`（XS-Leaks 表面审计：无 COOP/CORP/COEP/帧守卫的页面记 low）、
`--login-*` / `--oauth-*` / `--auth-*`（认证感知爬取，见上）、
`--checkpoint` / `--resume`（断点续扫）、`--rate-limit`（全局限速）、
`--proxy` / `--proxy-list`（出口代理/轮换）、`--rotate-headers` / `--jitter-ratio`（指纹与节奏扰动）、
`--second-order-*`（二次注入：注入点与查看点分离的存储型流）、
`--verify-fix` / `--diff`（对 JSON 报告重放确认修复情况）、
`--no-verify-ssl`。

**批量输入（Phase 87 P0/P1）：**

```bash
# 批量 URL 文件（每行一个，# 注释）→ 每个目标一份报告到 -o DIR
python -m xssentinel --batch urls.txt -o reports/

# 管道输入：侦察工具直接流式喂入（httpx/gau/wayback 输出兼容）
# （Pipe mode，一行一个 URL；TTY 下会提示需要管道输入）
httpx -l in.txt | python -m xssentinel --batch-stdin -o reports/

# HAR 导入：浏览器 DevTools / Burp / ZAP 导出的 .har 直接作为扫描入口
# 每个捕获到的请求 = 一个真实端点：method/form·JSON body/cookie/自定义头
# 全部回填后走完整扫描管线（对齐 Burp/XSpear 的 HAR 入口）
python -m xssentinel --har capture.har -o reports/ -f json

# OpenAPI/Swagger 导入：文档化的 API 契约直接作为扫描入口
# 每个 path+operation = 一个端点（含浏览器从未访问的路由）；路径模板
# {id} 解析为样本 URL，body 由 schema 构建，apiKey/bearer 转为请求头
python -m xssentinel --openapi openapi.json -o reports/ -f json
```

三个批量源（`--batch` / `--batch-stdin` / `--har` / `--openapi`）与 `-u` 互斥，报告均按目标
分文件写入 `-o DIR`；URL 去重、失败目标不中断整批、结束时汇总统计。

### 作为库调用

```python
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

sc = Scanner(requester=Requester(timeout=10))
sc.scan_target("https://example.com/search", method="GET", params={"q": "test"})
for f in sc.findings:
    print(f.data["type"], f.data["context"], f.data["payload"])
```

---

## 目录结构

```
xssentinel/
├── __main__.py            # CLI 入口（参数定义/策略预设/main 分发；Phase 43 拆分）
├── cli_runner.py            # 扫描执行：单目标 / async 单目标 / async 批量 / 报告写出
├── cli_commands.py          # 子命令：self-test / serve / verify-fix / diff / passive（Phase 44）
├── data/
│   └── payloads.json      # 上下文分类的 payload 语料（可自由扩展）
└── core/
    ├── requester.py       # HTTP 层（会话/代理/超时/SSL）
    ├── context.py         # 反射点上下文分析器
    ├── reflection_profile.py  # 反射画像（三明治探针 + 字符过滤反馈闭环）
    ├── generator.py       # 生成式 payload 构造器（仅用存活字符拼装）
    ├── pre_encode.py      # 自动预编码管道（base64/JWT/JSON 容器同构注入）
    ├── payloads.py        # payload 语料加载与按上下文检索
    ├── transform.py       # 23 种 WAF 绕过变形/编码家族（REGISTRY 为准）
    ├── waf.py             # WAF/拦截指纹识别
    ├── verifier.py        # 语义确认 + 无头确认（BeautifulSoup 结构化判定）
    ├── dom.py             # DOM XSS 静态污点分析
    ├── dom_engine.py      # DOM XSS 真·浏览器执行确认（Playwright 插桩 + 标记溯源）
    ├── poc.py             # 可复现 PoC 生成（curl / URL / 自包含 HTML）
    ├── scanner.py         # Scanner 核心类（L1 流水线/确认/去重；Phase 40 起
    │   │                  #  与 StoredBlind/AdvancedLayer/Crawl 三个 Mixin 组合）
    ├── scanner_stored.py  # StoredBlindMixin：L4 存储两步 + L5 盲打 OOB 收网
    ├── scanner_layers.py  # AdvancedLayerMixin：L3 DOM + L7 jsonp/csp/cors/mXSS/
    │   │                  #  clobber/template/polyglot
    ├── scanner_crawl.py   # CrawlMixin：SPA 无头爬取 + 隐藏参数挖掘 + BFS
    ├── cors_check.py      # 目标级 CORS 审计（Phase 51：Origin 反射 + 凭据判定）
    ├── xs_leaks.py        # XS-Leaks（Phase 53：隔离头审计 + 通道载荷库/演示 PoC）
    ├── findings.py        # Finding 数据类 + 默认变形阶梯（mixins 共享）
    ├── scenarios.py       # 声明式多步检测场景引擎（--scenarios，Nuclei 风格）
    ├── passive_proxy.py   # 被动代理扫描（Phase 44：捕获→去重→喂 L1，对标 xray/w13scan）
    ├── sqli.py            # SQLi 错误回显 grep 引擎（Phase 44，对标 dalfox/xray sqldet）
    ├── retire_js.py       # 过时 JS 库扫描（Phase 44，对标 XSStrike retireJS）
    ├── layers/            # 高级检测层实现包（Phase 39 拆分）
    │   ├── client_layers.py     # postMessage/原型污染/SW/Worker/重定向/框架/GraphQL/WS
    │   ├── transport_layers.py  # header/path/cookie/error 注入
    │   ├── content_layers.py    # markdown/TT/CSP nonce/cookie tossing/SRI/import map
    │   │                        # sanitizer/CSSI/dangling markup/SVG
    │   └── common.py            # 共享 _make_finding
    ├── advanced_layers.py # 高级层门面（run_* 入口 + 向后兼容 re-export）
    ├── fix_advice.py      # 修复建议引擎（语料在 data/fix_advice.json）
    └── report.py          # HTML / JSON / CSV / SARIF / JUnit / Markdown 报告（含 PoC 渲染）
tests/
├── vuln_server.py         # 本地脆弱测试服务（自测用，含 WAF 模拟端点）
├── run_self_test.py       # 逐层自检脚本
└── demo_scan.py           # 生成综合演示报告 demo_report.html / .json
```

---

## 自检 & 演示

本仓库自带一个**仅用于本地验证**的脆弱服务器，覆盖全部检测上下文：

```bash
# 终端 1：启动测试服务
python tests/vuln_server.py          # http://127.0.0.1:8899

# 终端 2：逐层自检（/safe 必须 0 命中）
python tests/run_self_test.py

# 生成综合报告
python tests/demo_scan.py            # 产出 tests/demo_report.html / .json

# 靶场 2：真实世界风格场景（半破损过滤器/上下文陷阱/二级存储/CSP nonce 泄露/
# DOM srcdoc·cookie·name 变体，Playwright 全链路确认）
python tests/run_range2.py           # 20 用例自动判定 TP/TN/FP/FN

# 被动代理演示（Phase 44）：起内建 origin + 被动代理 + 真实 Scanner，
# 回放 3 个浏览器式请求，验证 捕获→去重→扫描→发现→报告 全链路（含 /safe 零误报自检）
python tests/passive_demo.py         # 产出 tests/passive_demo_report.html
```

端点含义：`/echo`(HTML 元素)、`/attr`(双引号属性)、`/script`(脚本字符串)、
`/href`(href URI)、`/evt`(事件处理器)、`/dom`(DOM 污点)、
`/waf`(模拟 WAF 拦截 `<script>`，验证绕过层)、`/cdata`(CDATA 反射)、
`/meta`(meta-refresh 反射)、`/tpl`(`{{ }}` 模板反射)、
`/store`+`/view`(存储型 XSS)、`/safe`(html.escape，必须零误报)、
`/links`(爬虫 fixture：链接到上述多个端点 + POST 表单，用于验证深度爬虫/去重/PoC)。

验证结果（本地，全部层开启）：约 17 个发现（含反射 / DOM 动态确认 / 存储 / 盲打），WAF 被正确指纹识别，
`/safe` 端点在改进确认逻辑与盲打门控后**零误报**。`tests/run_self_test.py` 会断言每层均触发、`/safe` 为零（含 L6 真浏览器 DOM 确认），并单独用深度爬虫扫描 `/links` 验证发现去重与可复现 PoC 生成。

靶场 2（`tests/range2_server.py` + `tests/run_range2.py`）覆盖 benchmark 矩阵之外的真实世界缺陷：递归剥 script、单引号属性、onload 黑名单、空格过滤、mXSS 变异、未闭合引号属性、`--!>` 注释断点、正则字面量上下文、二级存储、**CSP nonce 泄露自动利用**（读取页内泄露的 nonce 构造同 nonce script，验证器对「nonce 与响应 CSP 头一致」的 script 放行——nonce 轮换的服务器不会被误确认）、iframe.srcdoc / cookie / window.name / 多跳 innerHTML 等 DOM 变体。当前成绩 **20 漏洞全报 / 6 安全零误报**（含 second_order 注入/查看双端点路径）——Phase 63 扩容后新增四类真实世界场景：JSON API（application/json 载体按文档 leaf 探测）、RESTful PUT multipart 上传 filename、CORS Origin 反射 + Allow-Credentials（high cors_misconfig）、XS-Leaks 无隔离面（--audit-xs-leaks 记 low），以及一个带 COOP/CORP/COEP 隔离头的安全负样本。

测试策略（Phase 37）：`tests/test_pipeline.py` 把靶场 2 的精简切片纳入 pytest —— **主流程回归在每次 pytest 就会暴露**，不再依赖手动靶场演练；`tests/test_async_pipeline.py` 补上 async 扫描器首批测试（曾靠 0% 覆盖掩盖了 `for_context` 缺失导致 async L1 静默失效的 bug）；core 的 verbose 诊断已统一路由到 `logger.debug`（`--verbose` 即 DEBUG 级）。Phase 43 补齐 `tests/test_fuzzer.py`（`--fuzz` 七个评分维度全断言，覆盖率 0%→全路径）与 `tests/test_form_miner.py`（表单抽取/填充/端点转换），并拆分 `__main__.py`（1145→497 行 + cli_runner/cli_commands）。Phase 44 新增三个测试文件共 42 例：`tests/test_passive_proxy.py`（签名去重/scope 匹配/body 解析/裸 socket 真代理端到端捕获 + 真实 Scanner 反射命中回归）、`tests/test_sqli.py`（五家族指纹全路径 + 真回显服务命中）、`tests/test_retire_js.py`（库名锚定版本提取防路径数字泄漏/版本区间边界/去重）。

**当前基线（2026-09-06 实测，Phase 93 后）**：双引擎 98 用例矩阵（预算 14/12/90，结果 `benchmark/results/post_audit_sync.json` / `post_audit_async.json`）：

| 引擎 | TP | FP | TN | FN | ERROR | recall | precision | FPR | 全矩阵耗时 |
|------|----|----|----|----|-------|--------|-----------|-----|-----------|
| sync | 64 | 0 | 34 | 0 | 0 | 1.000 | 1.000 | 0.000 | 809s |
| async | 60 | 0 | 34 | 4 | 0 | 0.938 | 1.000 | 0.000 | 526s |

sync 首次跑出**全绿**（旧基线有 6 个 safe 用例因 loopback 中断计 ERROR，从未真正评分）。async 的 4 个 FN（`neg-filter-05` / `pos-cdata-01` / `pos-tpl-01` / `pos-tpl-02`）单独复现**全部检出**（0.7–0.8s），仍是环境抖动。

两个引擎的 **1 + 5 个 FN 全部是环境抖动**（劣化 loopback 在满载下掐连接）：单独复现这 6 个用例**全部检出**（1.2–11.6s），且 sync 与 async 漏掉的用例集合完全不重叠——判定代码回归前必须先单跑复现。对照旧基线（`phase69_sync.json` / `phase68_async.json`，均为 recall/precision 1.000）时须注意：旧 sync 基线里 **6 个 safe 用例是 ERROR（从未真正评分）**，现在全部跑通为 TN；旧基线没暴露的 1 个 sync FP 与 3 个 async FP 已在 Phase 91/92 修掉（见下）。

**Phase 91/92：基准暴露的三个真实误报**（都可稳定复现，非环境问题）：
- `neg-escape-03`（sync+async）：Phase 84 放宽的 event_handler 回退正则把 `value='&#x27; onmouseover=alert(&#x27;TOK&#x27;)'` 当成真属性边界——引号被 html.escape 转成实体，浏览器里根本没跳出属性。改为 `_value_owner_attr()` 迷你 HTML tokenizer 走引号/未加引号值状态机；顺带修掉 `<img src=x/onerror=...>`（`/` 不终止未加引号值，lxml 实测 src 把它吞掉）。UTF-7 变换（`+ACY- onmouseover=...`）不含任何实体，也只有状态机能拦住。
- `neg-csp-01/03`（async）：`css_context` 分支（`<style>` 与 `style=`）完全没查 CSP，而 script_block / event_handler / url_javascript 都查了 → 严格 CSP 下仍确认可执行。已补闸门；`expression()`/`@import` 故意不放闸（那是 CSS，script-src 管不到）。
- `neg-escape-03`（async，url_javascript）：原闸门是"窗口内无实体"，UTF-7 类变换（`+ADw-iframe src=javascript:...`）零实体直接绕过。改为要求 sink 所属属性是 URI 类（href/src/content/...）。

**Phase 93：async 变慢的真正原因（推翻我此前 P85→P87→HEAD 的归因）**。cProfile 实测 `neg-escape-03`（23s）：扫描器自身只花 **0.33s**，**22.9s 停在 `GetQueuedCompletionStatus`——进程在睡觉，不在干活**。根因是 `AsyncScanner.jitter` 默认 **0.1**：与 sync 同名但语义完全不同——sync 的 jitter 是**限速间隔的比率**（不开 `--rate-limit` 就零开销），async 的却是**每个请求前固定睡 50–150ms**，而 `cli_runner.py` 两处构造都没传它，CLI 也没有开关能关掉（测试全都显式传 `jitter=0`，作者们早已在绕）。212 个请求 ≈ 21s，就是全部差距；传输本身实测 2.3ms/请求（keep-alive 与 force_close 无差别）。默认改 0.0（与 sync 对齐，限速改为显式 opt-in）后 `neg-escape-03` **23.3s → 0.47s**，async 全矩阵 **1525s → 526s**，反超 sync（809s）。同批把 sync 自 Phase 27-1 就有的"转义反射收敛"（3 载荷×2 变换、跳过反射画像三明治探针、跳过 WAF bypass 基座）移植进 async，三份 `_is_marker_escaped` 拷贝收敛为 `context.is_marker_escaped` 一份（对旧实现做 4 万随机输入差分，零行为变化）。

**Phase 94：层护栏（元修复落地）**。本次审计链路里所有"静默失效"（漏 import、契约错配）都是被宽 `except Exception` 在 DEBUG 级吞掉的——Phase 63 一次 AttributeError 让 async 静默丢掉全部 17 个页面层，Phase 84 漏 import 让 L9 参数挖掘"正常工作"实则什么都没做。现在：`core/layer_guard.py` 提供 `run_layer()`，**三个层分发器（22 个层调用点）全部挂上每层护栏**——一层失败不再杀死后续层；接线类异常（ImportError / NameError / UnboundLocalError / SyntaxError——这些永远不可能是目标的错）**升到 WARNING 并点名层**，其余（duck-typing / 形状探测里常见的 AttributeError / TypeError / KeyError）留在 DEBUG 免得狼来了；`BudgetExhausted` / `CircuitOpen` 照旧透传（预算停止是主动结束，不是层 bug）。async 的 `_drain_agen` 同步升级：`page_tasks` 改为 `(层名, agen)`，告警可定位到层；`scanner_crawl` 的 param_miner / js_miner 挖掘点同样接线告警。教训记录在案：护栏上线当天，作者自己重构分发调用时漏传 `scanner`，22 处 TypeError 全部被护栏静默吞掉——**这正是 TypeError 不能无脑升 WARNING 的原因，也是分发契约必须有测试锁住的原因**（`tests/test_layer_guard.py`，11 例）。

**Phase 95：反射画像驱动的转义收敛（Phase 27-1/93 判定失效的修复）**。给基准补上**请求数**记录（`evaluate_case` 提取报告顶层 `meta.requests`，`benchmark/req_stats.py` 分析分布）后立刻暴露两件事：① `scan_time_s` 在本机噪声达 **±25×**（同一用例 2s ↔ 77s，与请求数完全不相关——安全软件掐 loopback + Defender 扫子进程启动），**耗时列不能作为优化依据，请求数才是稳定度量**；② escaped 端点（`neg-escape-01` 等）照打 **203 请求全预算**——Phase 27-1 的 `is_marker_escaped` 检查 marker **邻居** 8 字符里有无实体，但纯字母数字 marker 回显在元素体里时邻居是页面自己的结构字符（`<div>` 的 `>` / `</div>` 的 `<`），服务端从不编码它们 → **判定在最典型的 escaped 端点上恒 False，收敛预算从未生效过**（Phase 93 的 async"修复"实则主要靠 jitter，判定本身同样失效）。修复分三层：**profile_reflection 窗口截断**（探针回显后的 `</div>` 结构标签把裸 `<`/`>` 污染进窗口被判 kept——截断到第一个 `<` 后跟字母/`/`/`!` 的结构标签起点）；**实体证据优先**（属性值场景里页面自己的闭合引号 `">` 落在窗口内，裸 `"` 抢答 kept——改为实体形态存在即判 encoded，裸字符仅在无实体痕迹时才算 kept）；**按上下文收敛表**（`PROFILE_CONVERGE_CRITICAL`：元素体/`<`、dq 属性/`"`、sq 属性/`'`、未引号属性/`>`——该上下文 breakout **必需**字符全部被**编码**（stripped 不算：剥除字符可被 %22/fullwidth 类变换还原，认 stripped 会引 FN）才收敛到 3 载荷×2 变换；url_href（`javascript:` 无需特殊字符）、script/comment/css/template 系（关键字符不在探针集）不进表，保守不收敛）。双引擎接线（sync `_prioritize_bases` 返回 profile 供二次判定；async 在 WAF bypass 前收敛并截断候选）。效果：`neg-escape-01/02` 203→41、`neg-attr-03` 203→41、`neg-escape-06` 203→70，全矩阵请求数 8087→7088；`neg-attr-01/02/04`（引号剥除）、`neg-jsonp`（script_block）、`neg-rcdata`（raw 反射）、`neg-csp-03`（nonce 非严格）仍 203 属**设计内保守**。全矩阵判定 TP64 FP0 TN34 FN0（1 个 timeout 单跑复现即 TP）；测试 66/66 文件全绿，新增 `tests/test_profile_convergence.py` 11 例；`test_phase33`/`test_phase35` 的 escaped fixture 改为**剥除型**（escaped 回显现在会收敛，剥除才对应"过滤器场景"的原测试意图）。工具：`benchmark/req_stats.py`（请求分布）、`benchmark/req_shape.py`（服务端视角请求形状）。

**Phase 96：RCDATA breakout 缺口（4 个基准"safe"实为真漏洞 + 引擎从没试过唯一可行的向量）**。收尾 Phase 95 时列的下一个候选是"rcdata 系 203 请求收敛"，量化前先做实验验证，结果直接推翻了前提：`neg-rcdata-01..04`（textarea/title/xmp）的 `_page`/`_page_raw` **都不转义**，实测 `</textarea><svg onload=alert(1)>` 四端点 **breakout 原样回显全部可行**——RCDATA 内直接注入惰性 ≠ 端点安全，闭合标签 breakout 是教科书级 OWASP 向量。CLI 全扫描 4 端点全报 0 finding（**真 FN**），定位链：**verifier 有完整 RCDATA 感知**（`_RCDATA_TAGS` + `_in_rcdata_raw` 向后扫描，Phase 35 注释明说"a genuine breakout AFTER the closing tag still confirms"，单测证实三种 breakout 回显全 confirmed=True）→ **确认链路完备，缺口 100% 在载荷选择层**：`data/payloads.json` 里没有任何 `</textarea>`/`</title>`/`</xmp>` 前缀载荷，引擎从不尝试。修复镜像 Phase 95 形状：`reflection_profile.detect_rcdata_tag()`（token 位置向后扫描未闭合 RCDATA 开标签，与 verifier 语义一致）→ profile 带 `rcdata_tag` 字段 → `surface_rcdata_breakouts()`（dict 版 sync / strs 版 async）取 top-4 候选前置 breakout 变体（payload_class=`rcdata_breakout`）。**sync 接线在 `_prioritize_bases` 之后外层**；async 初版误放进 `not full_reflection` 分支被测试抓住（raw 回显全字符 kept → full_reflection=True → 分支整个跳过 → breakout 零发送）——移到外层并用 `not marker_escaped` 防止收敛后重扩候选列表。**基准标注复核**：neg-rcdata-01..04 ground_truth safe→**vulnerable**（raw 回显下 breakout 可行即真 XSS），另加 4 个 `m_escape_rcdata_*` safe 孪生端点（neg-rcdata-05..08，html.escape 后直接注入与 breakout 双惰性，同时是 Phase 95 收敛在 RCDATA 场景的回归锚）。效果：4 端点 0→**4 findings（全部 high/high）**，请求 203→33-34/端点（breakout 变体命中即停）；verifier 零改动。测试：`test_profile_convergence.py` 11→**19 例**（detect 矩阵 / profile 字段 / dict+strs surfacing / sync+async raw echo 确认 / escaped 双路径预算回归）。

测试侧：**66 文件全绿**（2026-09-06 分文件跑法 842s）。新增 `tests/test_verifier_event_handler.py`（23 例）、`tests/test_verifier_uri_csp.py`（18 例）、`tests/test_async_escaped_convergence.py`（9 例）、`tests/test_layer_guard.py`（11 例）、`tests/test_profile_convergence.py`（19 例，Phase 95+96）、`test_verifier_uri_csp.py` 再补 5 例（Phase 98）共 **85 例**。

**Phase 96 基准新基线（102 用例标定口径 sync/async 14/12/90）**：sync **TP67 FP0 TN34 FN1**（recall 0.985 / precision 1.000 / f1 0.993，898s；FN1=pos-url-02 timeout，与 p95 相同）；async **TP62 FP0 TN34 FN6**（476s）——6 个 FN 全部集中在 260-366s 的 loopback 劣化窗口（WinError 10054 连墙），单跑复现 **6/6 全 TP**，有效口径 **TP68 FP0 TN34 FN0**。对照 p95（98 用例）：sync TP63→67、async TP62→有效 68，增量全部来自 rcdata 4 用例 TN→TP；**FP 保持双引擎 0**。请求数：全矩阵 sum 7088→**6548**（加 4 用例反降 540：rcdata raw 系 4×203→33-34，新增 4 个 escaped safe 各 41-42——Phase 95 收敛口径）；rcdata 系彻底退出 top-12 请求榜（榜内全部为 Phase 95 已核对的设计内保守用例）。结果：`benchmark/results/p96_sync.json` / `p96_async.json`。

**Phase 98：CSP nonce 覆盖 `'unsafe-inline'`（渗透实战形态实测抓到的系统性误报）**。从渗透视角做**形态矩阵实测**（不是代码清单复核）：构造 12 个真实世界高频形态（多处反射 ×5、JSON API、规则型 WAF、nonce CSP、DOM/hash sink、postMessage、双重 URL 编码、大小写过滤、Angular 表达式、RESTful 路径、CRLF），批量跑引擎检验实验室指标能否兑现。**10/12 检出**；多处反射 5/5 全过（靠 polyglot + Phase 96 breakout + 注释逃逸兜底——**该假设被证据否定，不是缺口**）；CRLF 0 finding 合理（头注入不属于 XSS）。唯一真缺口是 nonce CSP：现代应用主流写法 `script-src 'strict-dynamic' 'nonce-xxx' 'unsafe-inline'`，按 CSP Level 2+ **策略含 nonce/hash 时浏览器忽略 `'unsafe-inline'`**，裸内联脚本根本不执行；而 `verifier._csp_blocks_inline` 与 `csp.is_strict_inline` 两处都只做"`'unsafe-inline'` 存在即判可执行"，旧行为下靶场报出 `high/high` 而 PoC 永不触发的**系统性假阳性**。修复：`csp.unsafe_inline_overridden()`（script-src/default-src 含 nonce 或 sha256/384/512 源即判 unsafe-inline 失效；`'strict-dynamic'` 只影响 host 源，不计入）→ verifier 内联门接入。**Phase 36 nonce 泄漏利用不受影响**（携带策略声明 nonce 的脚本由 `_script_nonce_allowed` 放行，单测锁定不误杀）。实测效果：修复前确认载荷是裸 `<script>`（假阳性），修复后升级为 `<script nonce='页面真实 nonce'>`（**真实可利用**）——误报变成了真漏洞。测试：`test_verifier_uri_csp.py` 18→**23 例**。

**Phase 97：基准 FN 二次确认（把本轮手动 repro 6 个 FN 的流程自动化进 runner）**。`run_benchmark_batched.py` 现在对**形状像环境失败的 FN**（error 非空 / requests==0 / scan_time ≥ 0.9×timeout）自动复评一次：翻案则替换记录、首跑完整保留在 `fn_retry.first` 注记里（可审计，绝不静默丢弃）；复现仍 FN 或重试本身异常则如实保留 FN。**真代码 FN（正常完成、正常请求数、无 error）永不重试**——保留给人工判断，防止重试掩盖真实检测缺口。跨 run 对比须核对 `meta.fn_retry_on`（口径开关不同时 resume 会按 budget 变化丢弃旧结果，不静默混跑）。已验证：timeout=1 构造必现 FN 场景，触发→重试→仍 FN→注记保留全链路正确；`test_benchmark.py` 33/33 过。

**Phase 98：PoC 认证 header 回放（09-02 复审"PoC 回放会失败"的最后一块）**。`build_poc` 此前只回放 cookies——API 目标用 `Authorization: Bearer` / `X-API-Key` / 自定义反爬头认证时，无凭据 curl PoC 直接 401，客户/复测复现不了。现在 `--poc-auth` 开关语义扩展为"回放会话凭据（cookies **和** 可回放 headers）"：`attach_pocs`（sync + scanner_layers 镜像）取 `session.headers`，经 blocklist 过滤（host/content-length/content-type/connection/accept 系/cookie——cookie 走 `-b` 专道）后以 `-H` 逐条进 curl，含 header/cookie/path 三类 transport 载体 finding 分支；PoC dict 带 `replay_headers` 键供报告展示。默认仍 OFF（报告外发不泄露测试者会话）。测试 `tests/test_poc_replay_headers.py` 7 例（认证头入 curl、控制头过滤、POST+cookie+header 组合、transport 载体分支、无 headers 零变化、None 值剔除、upload 分支）。

**Phase 98b：async 路径的 PoC 凭据桥接（集成测试抓出的真缺口）**。async 引擎的 findings 经 `Scanner(requester=None)` shim 走报告链——该 shim 的 session 是**全新的空会话**，`attach_pocs` 读到的 cookies/headers 恒为空：**Phase 48 的 cookie 回放在 --async 模式下从未生效过，Phase 98 也会同样空转**。修复（cli_runner 两处 shim：单 URL + batch）：① 把 `asc.cookies`/`asc.headers`（CLI `-b`/`-H`/stealth UA 的真源）桥接进 shim 的 session；② shim 构造补传 `poc_include_auth`（此前开关也没传，闸门本身是关的）。附带修复：`AsyncScanner.__init__` 的 `asyncio.Lock()` 在 py3.9 于宿主环境（pytest/`--serve`/库嵌入）主线程隐式 loop 被消费时抛 RuntimeError——捕获后补建 loop 重试。新增集成测试 `test_async_cli_poc_replays_credentials`（真 CLI 参数 + 本地回显服务器 + 真 async 扫描，断言 PoC 同时含 `-b` 与 `-H`），8/8 过；全量回归 67/67 文件绿（1782s）。

**Phase 102：WAF 目标的端到端演练（此前零覆盖的实战主场景）**。大量真实目标在 Cloudflare/ModSecurity/Akamai 之后，`waf.py` 指纹与 `bypass.py` 厂商绕过链（Phase 91）都存在、扫描器见到 WAF 也会前置绕过变体，但**从未被整体验证过**。新增 `tests/test_waf_bypass_e2e.py`：伪 WAF 宣告自己（Server: cloudflare + CF-RAY + body 里的 Ray ID 注释）、403 掉两类朴素签名（`<script`、`<svg onload=`）、放行大小写/实体/UTF-7/unicode/`javascript:` 等形态。结论：**链路是通的**——引擎检出 Cloudflare → 走绕过链 → 命中确认（获胜载荷是 `<svg/onload=...>` 这类替代语法，而非被拦形态），对照组（无 WAF 头同一页面）正常。校准踩坑已写进文件注释：① 预算故意取小（4x3），满预算（~170 变体）在本机会偶发跑不到可确认变体而 flaky（曾出现 96s/128s 与零 finding）；② 若连 `onerror=`/`onload=` 一起拦（解码后大小写不敏感），目标比真实规则型 WAF 还硬，只有大预算能过——那测的是本机速度而非绕过逻辑。

**p101 基线（107 用例，退避版 fn-retry）**：sync **TP72 FP0 TN35 FN0**（f1=1.000），async **TP71 FP0 TN35 FN1**；`pos-dom-04` 首次 FN 经退避重试翻案为 **TP**（机制在真实跑动中生效），async 的 `neg-filter-06` 三次尝试均为 timeout 但 `requests=91`（请求全发出、只是慢）而单跑 0.83s 即 TP——属本机"慢而非断"的性能噪声。已知改进方向：FN 重试时放宽 timeout（`TIMEOUT×2`，仅重试路径并在 `fn_retry` 注记中记录），可消除这类假 FN。结果文件 `benchmark/results/p101_sync.json` / `p101_async.json`。

**Phase 101b：修掉一个我自己引入的挂死（异步锁的 loop 归属）**。Phase 98b 为 `AsyncScanner.__init__` 加的"宿主无 loop 时补建 loop"兜底是错的：py3.9 的 `asyncio.Lock()` 绑定**构造时**的 loop，构造函数自己装的 loop 与调用方 `asyncio.run()` 的 loop 不是同一个——锁绑在死 loop 上，每个 `async with lock` 永久挂起，把原本清晰的 RuntimeError 变成了**测试集挂死**（回归中 `test_csp_nonce_async_parity.py` 卡在 `asyncio._poll`）。正确修法是**惰性创建**：`_lock` 在 `__init__` 置 None，`_get_lock()` 在真正运行的 loop 里首次使用才构造（6 处 `async with self._lock` 全部改走 `_get_lock()`）；既不报错也不劫持宿主的 loop。新增契约测试 `test_host_loop_is_not_hijacked_by_scanner_construction`（宿主先 `set_event_loop` 再 `asyncio.run`，挂死即 pytest-timeout 失败）。全量回归 **70/70 文件绿**（723s，较修复前 1875s 大幅缩短——挂死消除）。

**Phase 101：FN 二次确认加退避与多轮重试**。Phase 97 的 fn-retry 只重试 1 次且无等待——p97 跑动里 `neg-rcdata-02` 在劣化窗口内**连超时两次、单跑 13 请求即 TP**，说明窗口能盖过一次立即重试。现在：重试最多 `FN_RETRY_MAX`（默认 2）次，间隔 `FN_RETRY_WAIT`（默认 20s，可用 `XSS_FN_RETRY_MAX`/`XSS_FN_RETRY_WAIT` 环境变量调）让窗口过去；`fn_retry.attempts` 记录**每一次**尝试的 verdict/耗时/请求数/error（首跑仍在 `first`）；任一次非劣化则立即停止（已翻案就不再消耗时间），全劣化则如实保留 FN 并在 meta 与日志中标注策略。`meta.fn_retry_max/wait` 在**写入时**读取（而非 import 时快照），确保描述的是真正生效的策略。测试 `tests/test_bench_fn_retry.py` 4 例（二次翻案、耗尽保留 FN、正常完成 FN 零重试、meta 记录策略）+ 端到端演练（timeout=1 构造必现 FN：attempts=3、退避 2s 生效、耗时 5.2s）。

**Phase 99：HTTPS MITM 端到端演练（补齐被动扫描实战价值的验证空白）**。`test_passive_mitm.py` 只证明传输层（TLS 拦截、参数进捕获队列）——但工程师装 CA 浏览一次目标站就能拿到**已验证 finding + 可回放 PoC**才是被动扫描的卖点，这条全链路此前零覆盖。新增 `tests/test_passive_mitm_e2e.py`：本地 TLS origin（raw 回显）+ MitmManager CA + `PassiveProxy(mitm_ca=...)` + `drain_captures` 后台 worker + 真 Scanner（`verify_ssl=False` 对自签 origin）——客户端经代理访问 `https://…/vuln?q=login` 一次，断言 `stats.mitm/scans ≥ 1`、finding 的 URL 为 https 且 param=q、`attach_pocs` 后 curl PoC 携带确认载荷。**一次通过，无需修产品代码**——并行会话的 Phase 50 MITM 实现质量过关；proxy/scanner 对自签 origin 均需 `verify_ssl=False`（文档级注意点）。

**Phase 100：async 侧 CSP nonce 泄漏利用（双引擎对偶缺口，基准抓出的真 FN）**。107 用例基准跑出 async **唯一一个非 timeout 的 FN**：`pos-csp-01`（`csp_nonce_ui_leak`，2.78s 正常完成），而 sync 是 TP（78.89s）。定位：**Phase 36 的 nonce-leak 利用 `_try_csp_nonce` 只在 sync 实现**，async 全文 `nonce` 仅出现在一行注释——`--async` 会静默漏掉所有 nonce 泄漏端点。修复：`_probe_param` 末尾（载荷循环与位置转移之后）加对偶实现，复用共享的 `csp.extract_nonces_from_csp` / `detect_nonce_near_marker`，发带**真实 nonce** 的 `<script nonce='N'>` 载荷，verifier 的 nonce 白名单仍防误报。**两个 async 专属坑**：① `text` 被载荷循环反复覆盖——必须用 marker 探测响应的快照（`probe_text`/`probe_headers`），否则检查的是最后一个载荷的响应，marker 与 nonce 都已不在；② 快照只能在探测处保存。测试 `tests/test_csp_nonce_async_parity.py` 2 例（检出 + 快照回归：nonce 只出现在探测响应时仍须检出）。效果：`pos-csp-01` FN→**TP（2.7s）**，async 有效口径 **TP72 FP0 TN35 FN0**（f1=1.000；本轮 neg-rcdata-02 两次劣化 timeout，单跑 13 请求即 TP）；全量回归 69/69 文件绿（1654s）。


API 攻击面加固：--serve 状态变更路由同源防御（Phase 70）+ Host 全方法校验（Phase 71）+ MITM CA 私钥 0600 与并发签名锁（Phase 72）。曾有两处结构性问题已修：`test_benchmark.py` 的 function-scope fixture 让每个测试重跑 6 端点 benchmark（需 1-2h）→ 改 module scope 共享一次运行后 **19 秒全过**（33 例）；`test_p27_api.py` 端到端偶发连接超时是劣化窗口掐 loopback（非代码问题，单跑必过）。

**基准工具链**：`benchmark/run_benchmark_batched.py [out.json] [batch] [port] [sync|async] [max_payloads] [max_transforms] [timeout]` —— 位置参数 4-7 可选，默认 sync/10/6/45；传 `sync 14 12 90` 才能复现 `python -m benchmark.runner` 的标定口径（旧基线就是 14/12/90，用默认 10/6 跑出来的数不能直接跟它比）。续跑时若检测到预算变了会丢弃旧结果而非静默合并。`benchmark/compare_runs.py A.json B.json` 做逐用例 diff（聚合分会掩盖"哪些用例移动了"，ERROR→FP 单独分桶，不会被当成改进）；`benchmark/repro_case.py CASE_ID [port] [sync|async]` 单跑一个用例并打印服务端原始回显 + 判定 + finding 详情——**排误报和验证 FN 是否是环境问题都用它**。

---

## 扩展指南

- **加 payload**：编辑 `data/payloads.json`，每条含 `context / payload / tags / confidence / note`，引擎自动按上下文选用。
- **加修复建议**：编辑 `data/fix_advice.json`（123+ 条，按 finding type 索引；`fix_advice.py` 是惰性加载器，API 不变）。
- **加检测场景**：编辑自己的场景 JSON（参考 `data/scenarios.example.json`）并 `--scenarios` 传入：按参数名匹配触发多步 HTTP 流（写入→读取→语义确认），`{token}`/`{param}` 占位符自动替换，适配存储型/二级流（Nuclei 风格）。
- **加绕过变形**：在 `core/transform.py` 的 `REGISTRY` 注册新函数即可被审计引擎调用。
- **加 WAF 指纹**：在 `core/waf.py` 的 `_WAF_SIGNATURES` 增加 `(名称, 正则)`。
- **加 sink/source**：扩展 `core/dom.py` 的源/汇列表。

---

## 已知限制

- 纯静态/语义确认对复杂上下文（嵌套模板、前端框架编译输出）可能漏报或需无头确认补强。
- 无头确认与 DOM 动态执行确认（L6）依赖 Playwright；未安装时自动跳过/优雅降级（DOM 层退化为静态启发式，反射层仍给出语义确认结论）。
- 爬虫为 BFS 轻量级实现（默认深度 2），复杂 SPA / 鉴权流建议配合 `--headless` 或人工提供入口；`--scope` 可把爬取限制在指定路径前缀内。
- 去重按 `(type, URL, param, context)` 合并同源同参的重复命中；DOM 类忽略 query 差异，避免同一页面的 hash/cookie 型 DOM XSS 被报两次。
- 可复现 PoC 对 DOM 类漏洞会用真实执行型 payload（`<img src=x onerror=alert(document.domain)>`）替换内部标记，确保 PoC 页面点开即触发。
- **盲打 XSS（L5）已支持自动确认**：`--oob self` 起本地监听器、`--oob interactsh` 用公共服务器，收到 beacon 即判定为已确认盲打；若超时未收到回调则不报（避免误判）。`interactsh` 模式需要公网可达的 callback 域名与网络连通，离线时优雅降级为"注入但未确认"。
- **存储型 XSS（L4）需要"展示页"**：你必须提供注入接口与其对应的展示/列表接口（如评论提交页 + 评论列表页），框架才会重新拉取确认持久化执行。
- 这是安全研究/授权测试工具，请勿用于未授权目标。
