# -*- coding: utf-8 -*-
"""Phase 111: layer-coverage matrix (static).

Phase 108 asked "which layers run but have no case?" for the vector
FAMILIES it could see in the manifest.  This does the inverse and
complete direction: take the engine's full layer list from
coverage.py and check, for every layer, whether ANY benchmark case can
make it produce a finding.

Static on purpose (no scanning): it is a map of what the benchmark does
NOT exercise, and it is the shopping list for the next wheel of case
writing.
"""
import io
import json
import os
import re

ROOT = "D:/qoder/xssentinel"

# layer -> the manifest modes that exercise it (or None if nothing does).
# Derived by reading the layer's detection module and grepping the modes.
COVERAGE = {
    "L1_reflected": (["raw_*", "attr_*", "escape_*", "comment_*", "rcdata_*",
                      "script_*", "svg_*", "math_*", "style_*", "cdata",
                      "base_href", "meta_refresh", "iframe_*", "href_*",
                      "output_*", "filter_*", "multi_*", "double_encode_safe",
                      "csp_*"], "wide"),
    "L2_waf_evade": (None, "no WAF-guarded target in the manifest -- the "
                            "bypass chain is only covered by "
                            "tests/test_waf_bypass_e2e.py"),
    "L3_dom_static": (["dom_hash_*", "dom_jquery_html", "dom_search_eval",
                       "dom_postmessage"], "yes"),
    "L4_stored": (["stored_write"], "added in Phase 110"),
    "L4_second_order": (None, "needs --second-order-inject/-viewers; no case"),
    "L5_blind_oob": (None, "needs an OOB listener configured; no case"),
    "L6_dom_dynamic": (["dom_*"], "yes"),
    "L7_mutation": (None, "the layer runs on every page but no target is "
                          "built to be exploitable ONLY by mutation"),
    "L7_dom_clobber": (None, "no clobbering-shaped target"),
    "L7_template": (["raw_template", "raw_template_vue"], "yes"),
    "L7_polyglot": (None, "the layer runs, but no target needs a polyglot "
                          "payload to fire"),
    "L7_jsonp": (["jsonp_whitelist", "jsonp_wrapped"], "yes"),
    "L7_csp": (["csp_strict_*", "csp_nonce_*"], "yes"),
    "L7_time_based": (None, "no time-delayed-sink target"),
    "L8_postmessage": (["dom_postmessage"], "yes"),
    "L8_prototype": (["prototype_vuln"], "added in Phase 113"),
    "L8_service_worker": (["sw_vuln"], "added in Phase 113"),
    "L8_web_worker": (["worker_vuln"], "added in Phase 113"),
    "L8_open_redirect": (["redirect_vuln"], "added in Phase 113"),
    "L8_framework": (["raw_template_vue"], "partial (Vue only)"),
    "L8_header": (["header_only"], "yes"),
    "L8_path": (["path_echo"], "added in Phase 109"),
    "L8_cookie": (["cookie_echo"], "added in Phase 109"),
    "L8_error_page": (["error_echo"], "added in Phase 109"),
    "L8_markdown": (["markdown_raw"], "added in Phase 109"),
    "L9_param_miner": (None, "crawl-time layer; no crawl case in the manifest"),
    # Phase 115: eleven layers that were live and dispatched but missing
    # from coverage.py's own LAYERS table (now registered).
    "L7_csp_nonce": (["csp_nonce_*"], "yes (csp_nonce_element/ui_element/ui_leak)"),
    "L7_css_injection": (None, "no CSS-injection target"),
    "L7_dangling_markup": (None, "no dangling-markup target"),
    "L7_import_map": (None, "no import-map target"),
    "L7_sanitizer_bypass": (None, "no sanitizer/DOMPurify target"),
    "L7_sri_bypass": (None, "no SRI target"),
    "L7_svg_xss": (["raw_svg*"], "yes (raw_svg family)"),
    "L8_cookie_tossing": (None, "no cookie-tossing target"),
    "L8_graphql": (None, "no GraphQL endpoint target"),
    "L8_trusted_types": (None, "no Trusted Types target"),
    "L8_websocket": (None, "no WebSocket target"),
    "L9_js_miner": (None, "crawl-time layer; no case"),
    "L9_form_miner": (None, "crawl-time layer; no case"),
}


def main():
    man = json.load(io.open(os.path.join(ROOT, "benchmark", "manifest.json"),
                            encoding="utf-8"))
    cases = man["cases"]
    modes = sorted({c["mode"] for c in cases})

    def has(pattern):
        if pattern.endswith("*"):
            pre = pattern[:-1]
            return any(m.startswith(pre) for m in modes)
        return pattern in modes

    rows = []
    for layer, (patterns, note) in COVERAGE.items():
        if patterns is None:
            covered, matched = False, []
        else:
            matched = [p for p in patterns if has(p)]
            covered = bool(matched)
        rows.append({"layer": layer, "covered": covered,
                     "modes": matched, "note": note})

    uncovered = [r for r in rows if not r["covered"]]
    out = {"cases": len(cases), "modes": len(modes),
           "layers": len(rows), "covered": len(rows) - len(uncovered),
           "uncovered": len(uncovered), "rows": rows,
           "uncovered_layers": [r["layer"] for r in uncovered]}

    jp = os.path.join(ROOT, "benchmark", "results", "layer_coverage.json")
    io.open(jp, "w", encoding="utf-8").write(
        json.dumps(out, ensure_ascii=False, indent=2))

    lines = ["# Layer coverage matrix (static, Phase 111)", "",
             f"Benchmark: {len(cases)} cases / {len(modes)} modes  ",
             f"Engine layers: {len(rows)}  ",
             f"Covered by at least one case: {out['covered']}  ",
             f"NOT covered: {out['uncovered']}", "",
             "| layer | covered | exercising modes | note |",
             "|---|---|---|---|"]
    for r in rows:
        mark = "yes" if r["covered"] else "**NO**"
        mods = ", ".join(r["modes"]) if r["modes"] else "-"
        lines.append(f"| {r['layer']} | {mark} | {mods} | {r['note']} |")
    lines += ["", "## Uncovered layers (the shopping list)", ""]
    for r in uncovered:
        lines.append(f"- `{r['layer']}` -- {r['note']}")
    md = os.path.join(ROOT, "benchmark", "results", "layer_coverage.md")
    io.open(md, "w", encoding="utf-8").write("\n".join(lines))

    print(f"cases={len(cases)} modes={len(modes)} layers={len(rows)} "
          f"covered={out['covered']} uncovered={out['uncovered']}")
    print("uncovered:", ", ".join(out["uncovered_layers"]))
    print("saved:", md)


if __name__ == "__main__":
    main()
