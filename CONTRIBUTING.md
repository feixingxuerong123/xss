# 参与开发

围绕 XSSentinel 做开发的实操指引。安装与使用见 [README](README.md);当前迭代
进度与历史决策记录见 [AGENTS.md](AGENTS.md)。

## 开发环境

```bash
git clone <repo> && cd xssentinel
python -m venv .venv && .venv/Scripts/pip install -U pip   # Windows; POSIX 用 .venv/bin/
pip install -e ".[dev,async,ast,headless,api]"
playwright install chromium        # 仅 headless 确认层需要
```

- Python >= 3.9(3.9 上实测可安装运行;CI 跑 3.11)。
- core 仅依赖 requests / beautifulsoup4 / lxml,其余能力全部走 extras,按需安装。

## 测试

**必须用分批 runner,不要裸跑单进程 pytest**——个别长预算文件在单进程下会
互相拖垮:

```bash
python tests/run_all_batched.py --quiet   # 全量逐文件门禁(本机约 60-75 分钟)
python -m pytest tests/test_report.py -q  # 单文件快速迭代
```

- runner 对每个文件独立 540s 预算(可覆盖),失败/超时才写日志到
  `benchmark/results/regression_logs/<时间戳>/`。
- `tests/test_benchmark.py` 在部分 Windows 机器会挂满 2×540s 预算(安全软件
  间歇性掐 loopback TCP,见 `dev/WEDGE_test_benchmark_20260927.md`);runner
  按失败记账。CI 的干净 runner 上它正常通过——以 CI 为准,本机红灯先判断
  是否为环境伪影(复跑、隔离跑)。
- `pyproject.toml` 已配置 pytest-timeout / rerunfailures(本机 loopback 抖动
  由一次自动重跑吸收;真回归会连续两次失败)。

## 回归靶场(改判定层必跑)

```bash
python -m benchmark.runner --quick   # 98 例快速精度矩阵(双引擎口径见 --engine)
python range3/runner.py --engine both    # 异形应用靶场,ground truth 独立撰写
python range4/runner.py --engine both    # React/Vue 真实框架 SPA 靶场(FN/FP/ERROR ⇒ exit 1)
```

改动上下文分类、payload 选择、判定/评分路径时,这三个靶场是行为契约;
只改报告 UI / 导出格式时跑 `tests/test_report*.py` 系列即可。

## 架构约定(改代码前必读)

- **scanner.py 已 Mixin 拆分**(主文件 + `scanner_layers` / `scanner_crawl` /
  `scanner_stored`):新增检测能力进对应 Mixin,不要堆回主文件。主文件顶部的
  层模块导入看似 F401,是 Mixin 运行时引用的故意导入,不要"清理"。
- **多步检测优先写场景 DSL**(`scenarios.py`),而非过程式代码。
- **fix_advice.py 数据化**(引擎 + JSON 语料):改修复建议优先改
  `xssentinel/data/fix_advice.json` 语料。
- **HTML 交付物统一走 `core/report_theme.py`**(主报告 / verify-fix / diff /
  benchmark 四处共享):改 UI 改主题模块,不要在报告生成器里内嵌样式拷贝。
- **报告自身的 XSS 安全契约**:所有动态内容必须 `_esc()` 转义;URL 只有
  http(s) 才渲染为链接(`_safe_url`);客户端 JS 全静态、零数据插值。
  `tests/test_report.py` / `test_p23.py` / `test_report_formats.py` 锁住这些,
  改报告必跑。
- 主流程里任何"看起来没用"的调用可能是诚实话术的一部分(scan_status /
  BOUNDED READ / coverage 失败路径),动手前先读注释——这个仓库的注释写的
  都是"为什么",不是"是什么"。

## 仓库约定

- `_` 前缀文件/目录 = 探针 / 日志 / 一次性产物,不入库(根目录与 dev/ 同规)。
- `benchmark/results/*.json` 历史跑分证据保留入库;新的跑分产物自行决定是否提交。
- LLM provider 配置带密钥:**绝不入库**,模板是
  `xssentinel/data/llm_providers.example.json`(运行期状态 `llm_state.json`
  同样被忽略)。
- 提交信息:一行主题说清"什么 + 结果",正文列要点(参考 `git log`)。

## CI

`.github/workflows/ci.yml` 三个 job:

| job | 触发 | 内容 |
|---|---|---|
| tests | push / PR | 全量 pytest + 快速精度矩阵 + range3 + range4 |
| benchmark-full | 手动 / 定时 | 完整 192 例双引擎矩阵 |
| nightly-gate | 每日定时 | 全量分批门禁(与本地 run_all_batched 同口径) |

PR 只需保证 tests job 绿; nightly 红灯先看是否为已知环境问题。
