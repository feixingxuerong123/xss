# Layer coverage matrix (static, Phase 111)

Benchmark: 121 cases / 120 modes  
Engine layers: 28  
Covered by at least one case: 14  
NOT covered: 14

| layer | covered | exercising modes | note |
|---|---|---|---|
| L1_reflected | yes | raw_*, attr_*, escape_*, comment_*, rcdata_*, output_*, filter_*, multi_*, double_encode_safe, csp_* | wide |
| L2_waf_evade | **NO** | - | no WAF-guarded target in the manifest -- the bypass chain is only covered by tests/test_waf_bypass_e2e.py |
| L3_dom_static | yes | dom_hash_*, dom_jquery_html, dom_search_eval, dom_postmessage | yes |
| L4_stored | yes | stored_write | added in Phase 110 |
| L4_second_order | **NO** | - | needs --second-order-inject/-viewers; no case |
| L5_blind_oob | **NO** | - | needs an OOB listener configured; no case |
| L6_dom_dynamic | yes | dom_* | yes |
| L7_mutation | **NO** | - | the layer runs on every page but no target is built to be exploitable ONLY by mutation |
| L7_dom_clobber | **NO** | - | no clobbering-shaped target |
| L7_template | yes | raw_template, raw_template_vue | yes |
| L7_polyglot | **NO** | - | the layer runs, but no target needs a polyglot payload to fire |
| L7_jsonp | yes | jsonp_whitelist, jsonp_wrapped | yes |
| L7_csp | yes | csp_strict_*, csp_nonce_* | yes |
| L7_time_based | **NO** | - | no time-delayed-sink target |
| L8_postmessage | yes | dom_postmessage | yes |
| L8_prototype | **NO** | - | no prototype-pollution target |
| L8_service_worker | **NO** | - | no service-worker target |
| L8_web_worker | **NO** | - | no worker target |
| L8_open_redirect | **NO** | - | no redirect-echo target |
| L8_framework | yes | raw_template_vue | partial (Vue only) |
| L8_header | yes | header_only | yes |
| L8_path | yes | path_echo | added in Phase 109 |
| L8_cookie | yes | cookie_echo | added in Phase 109 |
| L8_error_page | yes | error_echo | added in Phase 109 |
| L8_markdown | yes | markdown_raw | added in Phase 109 |
| L9_param_miner | **NO** | - | crawl-time layer; no crawl case in the manifest |
| L9_js_miner | **NO** | - | crawl-time layer; no case |
| L9_form_miner | **NO** | - | crawl-time layer; no case |

## Uncovered layers (the shopping list)

- `L2_waf_evade` -- no WAF-guarded target in the manifest -- the bypass chain is only covered by tests/test_waf_bypass_e2e.py
- `L4_second_order` -- needs --second-order-inject/-viewers; no case
- `L5_blind_oob` -- needs an OOB listener configured; no case
- `L7_mutation` -- the layer runs on every page but no target is built to be exploitable ONLY by mutation
- `L7_dom_clobber` -- no clobbering-shaped target
- `L7_polyglot` -- the layer runs, but no target needs a polyglot payload to fire
- `L7_time_based` -- no time-delayed-sink target
- `L8_prototype` -- no prototype-pollution target
- `L8_service_worker` -- no service-worker target
- `L8_web_worker` -- no worker target
- `L8_open_redirect` -- no redirect-echo target
- `L9_param_miner` -- crawl-time layer; no crawl case in the manifest
- `L9_js_miner` -- crawl-time layer; no case
- `L9_form_miner` -- crawl-time layer; no case