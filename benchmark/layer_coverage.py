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
                      "script_*", "svg_*", "math_*", "style_*", "raw_cdata",
                      "raw_base_href", "raw_meta_refresh", "iframe_*", "href_*",
                      "output_*", "filter_*", "multi_*", "double_encode_safe",
                      "csp_*"], "wide"),
    "L2_waf_evade": (["waf_naive"], "added in Phase 118 (pseudo-WAF target)"),
    "L3_dom_static": (["dom_hash_*", "dom_jquery_html", "dom_search_eval",
                       "dom_postmessage"], "yes"),
    "L4_stored": (["stored_write"], "added in Phase 110"),
    "L4_second_order": (["so2_write"], "added in Phase 126 (inject at A, verify viewer B; needs second_order_view_path)"),
    "L5_blind_oob": (["blind_vuln"], "added in Phase 124 (real OOB callback; needs extra_args --oob self)"),
    "L6_dom_dynamic": (["dom_*"], "yes"),
    "L7_mutation": (["mx_vuln"], "added in Phase 128 (raw reflection + a mutating sink in a script region; Phase 128 also killed the escaping-blind FP in the mXSS confirm path)"),
    "L7_dom_clobber": (["clobber_vuln"], "added in Phase 123 (needs a REAL id/name attribute -- Phase 123 also fixed the layer's escaping-blind FP)"),
    "L7_template": (["raw_template", "raw_template_vue"], "yes"),
    "L7_polyglot": (["waf_naive"], "reached via the WAF case (Phase 118) -- "
                                   "the bypass that lands is a polyglot"),
    "L7_jsonp": (["jsonp_whitelist", "jsonp_wrapped"], "yes"),
    "L7_csp": (["csp_strict_*", "csp_nonce_*"], "yes"),
    "L7_time_based": (["tb_vuln"], "added in Phase 125 (CSP fallback; Phase 125 also fixed the layer never starting its own OOB listener)"),
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
    "L9_param_miner": (["pm_vuln"], "added in Phase 121"),
    # Phase 115: eleven layers that were live and dispatched but missing
    # from coverage.py's own LAYERS table (now registered).
    "L7_csp_nonce": (["csp_nonce_*"], "yes (csp_nonce_element/ui_element/ui_leak)"),
    "L7_css_injection": (["cssi_vuln"], "added in Phase 122 (static page analysis)"),
    "L7_dangling_markup": (["dangling_vuln"], "added in Phase 116"),
    "L7_import_map": (["importmap_vuln"], "added in Phase 116"),
    "L7_sanitizer_bypass": (["sanitizer_vuln"], "added in Phase 117"),
    "L7_sri_bypass": (["sri_vuln"], "added in Phase 116"),
    "L7_svg_xss": (["raw_svg*"], "yes (raw_svg family)"),
    "L8_cookie_tossing": (None, "no cookie-tossing target"),
    "L8_graphql": (["graphql_vuln"], "added in Phase 117"),
    "L8_trusted_types": (["tt_vuln"], "added in Phase 116"),
    "L8_websocket": (["ws_vuln"], "added in Phase 116"),
    # Phase 115: ids found by the reconciliation test (scanner.py /
    # async_scanner.py / advanced_layers.py) -- helpers and probe stages
    # included, so the matrix shows the whole engine.
    "L1_csp_gate": (["csp_*"], "helper: runs before CSP-sensitive probes"),
    "L1_pre_encoded": (["pe_vuln"], "added in Phase 122 (param_value container)"),
    "L1_reflection_profile": (["raw_*", "attr_*"], "helper: runs on every reflection case"),
    "L2_position_shift": (["pshift_vuln"], "added in Phase 122 (WAF guards body only)"),
    "L7_cors": (["cors_reflect"], "added in Phase 113"),
    "L7_nonce_bypass": (["csp_nonce_*"], "partial (nonce-leak chain)"),
    "L7_xsleak": (["xs_vuln"], "added in Phase 128 (header-surface audit pair; opt-in --audit-xs-leaks, finding is severity low)"),
    "L8_request": (["raw_*"], "helper: request-level checks on every case"),
    "L9_scenario": (["sc_write"], "added in Phase 127 (declarative recipe; Phase 127 also fixed the {param} placeholder never being expanded in the step field name)"),
    "L9_upload_filename": (["upload_echo"], "added in Phase 110"),
    "L9_js_miner": (["crawl_js_vuln"], "added in Phase 120 (behavioural)"),
    "L9_form_miner": (["crawl_form_vuln"], "added in Phase 120 (behavioural)"),
}


def coverage_modes() -> set:
    """Every manifest mode referenced by the map."""
    out = set()
    for patterns, _note in COVERAGE.values():
        if patterns:
            out.update(patterns)
    return out


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
