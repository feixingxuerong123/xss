# Layer coverage matrix (static, Phase 111)

Benchmark: 170 cases / 167 modes  
Engine layers: 49  
Covered by at least one case: 45  
NOT covered: 4

| layer | covered | exercising modes | note |
|---|---|---|---|
| L1_reflected | yes | raw_*, attr_*, escape_*, comment_*, rcdata_*, raw_cdata, raw_base_href, raw_meta_refresh, output_*, filter_*, multi_*, double_encode_safe, csp_* | wide |
| L2_waf_evade | yes | waf_naive | added in Phase 118 (pseudo-WAF target) |
| L3_dom_static | yes | dom_hash_*, dom_jquery_html, dom_search_eval, dom_postmessage | yes |
| L4_stored | yes | stored_write | added in Phase 110 |
| L4_second_order | yes | so2_write | added in Phase 126 (inject at A, verify viewer B; needs second_order_view_path) |
| L5_blind_oob | yes | blind_vuln | added in Phase 124 (real OOB callback; needs extra_args --oob self) |
| L6_dom_dynamic | yes | dom_* | yes |
| L7_mutation | **NO** | - | the layer runs on every page but no target is built to be exploitable ONLY by mutation |
| L7_dom_clobber | yes | clobber_vuln | added in Phase 123 (needs a REAL id/name attribute -- Phase 123 also fixed the layer's escaping-blind FP) |
| L7_template | yes | raw_template, raw_template_vue | yes |
| L7_polyglot | yes | waf_naive | reached via the WAF case (Phase 118) -- the bypass that lands is a polyglot |
| L7_jsonp | yes | jsonp_whitelist, jsonp_wrapped | yes |
| L7_csp | yes | csp_strict_*, csp_nonce_* | yes |
| L7_time_based | yes | tb_vuln | added in Phase 125 (CSP fallback; Phase 125 also fixed the layer never starting its own OOB listener) |
| L8_postmessage | yes | dom_postmessage | yes |
| L8_prototype | yes | prototype_vuln | added in Phase 113 |
| L8_service_worker | yes | sw_vuln | added in Phase 113 |
| L8_web_worker | yes | worker_vuln | added in Phase 113 |
| L8_open_redirect | yes | redirect_vuln | added in Phase 113 |
| L8_framework | yes | raw_template_vue | partial (Vue only) |
| L8_header | yes | header_only | yes |
| L8_path | yes | path_echo | added in Phase 109 |
| L8_cookie | yes | cookie_echo | added in Phase 109 |
| L8_error_page | yes | error_echo | added in Phase 109 |
| L8_markdown | yes | markdown_raw | added in Phase 109 |
| L9_param_miner | yes | pm_vuln | added in Phase 121 |
| L7_csp_nonce | yes | csp_nonce_* | yes (csp_nonce_element/ui_element/ui_leak) |
| L7_css_injection | yes | cssi_vuln | added in Phase 122 (static page analysis) |
| L7_dangling_markup | yes | dangling_vuln | added in Phase 116 |
| L7_import_map | yes | importmap_vuln | added in Phase 116 |
| L7_sanitizer_bypass | yes | sanitizer_vuln | added in Phase 117 |
| L7_sri_bypass | yes | sri_vuln | added in Phase 116 |
| L7_svg_xss | yes | raw_svg* | yes (raw_svg family) |
| L8_cookie_tossing | **NO** | - | no cookie-tossing target |
| L8_graphql | yes | graphql_vuln | added in Phase 117 |
| L8_trusted_types | yes | tt_vuln | added in Phase 116 |
| L8_websocket | yes | ws_vuln | added in Phase 116 |
| L1_csp_gate | yes | csp_* | helper: runs before CSP-sensitive probes |
| L1_pre_encoded | yes | pe_vuln | added in Phase 122 (param_value container) |
| L1_reflection_profile | yes | raw_*, attr_* | helper: runs on every reflection case |
| L2_position_shift | yes | pshift_vuln | added in Phase 122 (WAF guards body only) |
| L7_cors | yes | cors_reflect | added in Phase 113 |
| L7_nonce_bypass | yes | csp_nonce_* | partial (nonce-leak chain) |
| L7_xsleak | **NO** | - | no XS-Leak target |
| L8_request | yes | raw_* | helper: request-level checks on every case |
| L9_scenario | **NO** | - | no --scenarios case |
| L9_upload_filename | yes | upload_echo | added in Phase 110 |
| L9_js_miner | yes | crawl_js_vuln | added in Phase 120 (behavioural) |
| L9_form_miner | yes | crawl_form_vuln | added in Phase 120 (behavioural) |

## Uncovered layers (the shopping list)

- `L7_mutation` -- the layer runs on every page but no target is built to be exploitable ONLY by mutation
- `L8_cookie_tossing` -- no cookie-tossing target
- `L7_xsleak` -- no XS-Leak target
- `L9_scenario` -- no --scenarios case