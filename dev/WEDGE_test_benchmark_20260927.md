# 已知未解:test_benchmark 进程内 connect 无限挂起(2026-09-27)

## 现象
`pytest tests/test_benchmark.py` 的 `benchmark_result` fixture(tests/benchmark.py:254
的 `run_benchmark`)里,Scanner 的 L1 marker 探针(scanner.py:527)在
`sock.connect` 上挂起,**远超** urllib3 应有的 10 秒 settimeout——py-spy 两次采样
(间隔 120 秒)都在同一帧,主线程零 CPU。

## 已排除
* fixture 服务器 accept 循环活着(py-spy: `serve_forever` 正常轮询);
* 服务器对**独立进程**的请求 4-20ms 响应(18899 端口健康);
* 端口保留段已迁出(18777/18899/18991/18999 实测可绑,见 cd360ff);
* `_send` 显式传 `timeout=self.timeout`(requester.py:313/326),shim 的
  Requester 是 `Requester(timeout=10)`(tests/benchmark.py:237)。

## 矛盾点(下次会话的切入)
settimeout(10) 的 connect 不可能挂 600 秒——除非:
1. 超时在 requests→urllib3 的某条路径上丢失(HTTPAdapter(max_retries=2)
   的 Retry 链是否重建了无超时连接?);或
2. 安全软件对该进程(今日已发数千连接)做了逐进程的连接拦截/限速,
   且其拦截发生在绕过 socket 超时的层(TDI/WFP 重定向);
3. 同进程内 ThreadingHTTPServer(keep-alive 常驻线程)与客户端池之间的
   某种 GIL/握手死锁——但 connect 阶段双方都应释放 GIL。

## 建议复现路径
1. 最小化:单进程起 ThreadingHTTPServer(protocol_version="HTTP/1.1")+
   requests.Session 发 5000 个请求,观察 TIME_WAIT 与后续 connect 延迟;
2. 若复现:py-spy dump 前后对比 + `netsh trace` 抓 loopback SYN;
3. 若不复现:门禁跑满一轮后立即重跑 test_benchmark(进程态相关性)。

## 关联
* 三个 fixture 服务器已启用 HTTP/1.1 keep-alive(cd360ff 之后的未提交改动,
  正确性独立成立:响应都带 Content-Length);
* 本机安全软件今日行为:SYN 黑洞(每次 connect 吃满 10 秒)、部分端口
  10013 拒绝、间歇 10053/10054 重置——与健康窗口交替出现。
