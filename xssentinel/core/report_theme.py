"""Shared design system for every XSSentinel HTML deliverable.

Four modules emit standalone HTML reports (report.build_html, verify_fix
.build_html, diff_report.diff_report_html, benchmark/report.py) and all
four used to carry a private hand-rolled copy of the same stylesheet --
four places to fix a contrast bug, four places that drifted apart, and
none of them readable in a dark room at 2am during an incident.

This module is the single source of that chrome:

  * ``base_css(extra)``   -- design tokens (light AND dark), components
  * ``theme_boot_script()`` -- <head> snippet that pins the theme before
                               first paint (no flash of wrong theme)
  * ``interactive_js()``  -- one defensive script shared by all pages:
                               theme toggle, findings toolbar (severity
                               chips / type select / text search), column
                               sorting, copy-to-clipboard, print helper.
                               Every lookup is null-guarded, so pages
                               without a toolbar simply no-op.

Design rules, on purpose:
  * ZERO external dependencies.  A report is opened offline, on a plane,
    on an air-gapped engagement laptop -- no CDN, no fonts, no framework.
  * The JS is fully static: it never interpolates report data, and it
    only touches classList / textContent of its OWN chrome.  Findings
    are rendered server-side and escaped; the client script must never
    become a second, unescaped path for attacker-controlled strings.
  * No-JS is a supported mode: with scripting disabled the report is
    still complete -- filters/sort/copy just don't exist, and the theme
    falls back to the OS preference via the ``prefers-color-scheme``
    media query in the CSS.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Design tokens.  DARK_VARS is emitted twice: once under [data-theme="dark"]
# (explicit toggle, JS-persisted) and once inside a prefers-color-scheme
# media query guarded by :not([data-theme="light"]) so that a report opened
# with scripting disabled still follows the OS.  One source, two consumers.
# ---------------------------------------------------------------------------

_LIGHT_VARS = """
 :root{
  color-scheme:light;
  --bg:#f4f6fb; --surface:#ffffff; --surface-2:#f0f2f7; --surface-3:#fafbfc;
  --text:#1f2430; --text-muted:#525b6b; --text-faint:#8a93a6;
  --border:#e5e8f0; --border-strong:#cfd5e2;
  --accent:#2f6bff; --accent-weak:#e8eeff;
  --code-bg:#eef0f6; --code-text:#242a38;
  --pre-bg:#141824; --pre-text:#dce2f0;
  --sev-crit:#b42318; --sev-high:#dc3d43; --sev-med:#c77414; --sev-low:#2563eb;
  --sev-ok:#17803d;
  --sev-crit-weak:#fee4e2; --sev-high-weak:#fee4e2; --sev-med-weak:#fef0c7;
  --sev-low-weak:#d1e0ff; --sev-ok-weak:#d1fadf;
  --header-bg:linear-gradient(135deg,#171c2e 0%,#1f2740 55%,#233055 100%);
  --header-text:#f2f5ff;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.1);
  --focus:#2f6bff;
 }
"""

# Token declarations only (no selector) so both consumers below stay
# provably brace-balanced: the explicit [data-theme="dark"] block and the
# no-JS prefers-color-scheme fallback reuse the identical declarations.
_DARK_DECLS = """
   color-scheme:dark;
   --bg:#0e1118; --surface:#161b26; --surface-2:#1d2330; --surface-3:#171c28;
   --text:#e3e7f2; --text-muted:#a6afc4; --text-faint:#6d7891;
   --border:#272e40; --border-strong:#39415a;
   --accent:#7aa2ff; --accent-weak:#1c2740;
   --code-bg:#222939; --code-text:#d5dcf0;
   --pre-bg:#0a0d15; --pre-text:#c9d3ee;
   --sev-crit:#ff8a80; --sev-high:#ff7a85; --sev-med:#ffc46b; --sev-low:#79a7ff;
   --sev-ok:#4ade80;
   --sev-crit-weak:#3a1d1f; --sev-high-weak:#3a1d22; --sev-med-weak:#382a14;
   --sev-low-weak:#1b2a4a; --sev-ok-weak:#12301e;
   --header-bg:linear-gradient(135deg,#0b0e1a 0%,#131a2e 55%,#182342 100%);
   --header-text:#eef2ff;
   --shadow:0 1px 2px rgba(0,0,0,.4),0 1px 3px rgba(0,0,0,.35);
   --focus:#7aa2ff;
  """

_DARK_VARS = '\n [data-theme="dark"]{' + _DARK_DECLS + "\n }\n"

_DARK_MEDIA = ('\n @media (prefers-color-scheme: dark){'
               '\n  :root:not([data-theme="light"]){'
               + _DARK_DECLS + "\n  }\n }\n")


def base_css(extra: str = "") -> str:
    """The shared stylesheet.  ``extra`` appends page-specific component
    CSS AFTER the base so it can override (benchmark metric cards, diff
    verdict badges, ...).  Every class an emitting module already uses is
    styled here -- the markup contracts did not move, only the paint."""
    return (
        "*,*::before,*::after{box-sizing:border-box}\n"
        + _LIGHT_VARS
        + _DARK_VARS
        + _DARK_MEDIA
        + _BASE_RULES
        + (extra or "")
    )


_BASE_RULES = """
 html{-webkit-text-size-adjust:100%}
 body{margin:0;background:var(--bg);color:var(--text);
      font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif}
 a{color:var(--accent)}
 :focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:4px}
 ::selection{background:var(--accent-weak)}
 code,kbd,pre{font-family:ui-monospace,Consolas,"Cascadia Mono",Menlo,monospace}
 code{background:var(--code-bg);color:var(--code-text);padding:2px 5px;border-radius:5px;
      font-size:.92em;word-break:break-all}
 pre{background:var(--pre-bg);color:var(--pre-text);padding:10px 12px;border-radius:8px;
     white-space:pre-wrap;word-break:break-all;overflow:auto;font-size:12px;line-height:1.5}
 pre code{background:transparent;color:inherit;padding:0}
 h1,h2,h3,h4{line-height:1.3}
 details>summary{cursor:pointer;color:var(--accent);font-size:12px;user-select:none}
 details>summary:hover{text-decoration:underline}
 details[open]>summary{margin-bottom:6px}

 /* ---- header ------------------------------------------------------------ */
 header{position:relative;background:var(--header-bg);color:var(--header-text);
        padding:22px 28px 20px;border-bottom:3px solid var(--accent)}
 header h1{margin:0;font-size:21px;font-weight:650;letter-spacing:.2px;
           display:flex;align-items:center;gap:12px;flex-wrap:wrap}
 .brandmark{flex:none;width:26px;height:26px;color:var(--accent)}
 .meta{color:var(--text-faint);font-size:12.5px;margin-top:7px;word-break:break-word}
 .meta b,.meta strong{color:inherit}
 .head-tools{position:absolute;top:20px;right:24px;display:flex;gap:8px}
 .head-tools .btn{background:rgba(255,255,255,.08);color:var(--header-text);
       border:1px solid rgba(255,255,255,.28);border-radius:8px;padding:4px 11px;
       font-size:14px;line-height:1.4;cursor:pointer;font-family:inherit}
 .head-tools .btn:hover{background:rgba(255,255,255,.17)}

 /* ---- summary cards ------------------------------------------------------ */
 .summary{display:flex;gap:14px;padding:20px 28px 4px;flex-wrap:wrap;align-items:stretch}
 .card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
       padding:14px 20px 12px;box-shadow:var(--shadow);min-width:126px;flex:0 1 auto;
       border-top:3px solid var(--border-strong)}
 .card .n{font-size:30px;font-weight:700;line-height:1.15;font-variant-numeric:tabular-nums}
 .card .lbl{font-size:12px;color:var(--text-muted);margin-top:2px;letter-spacing:.3px}
 .card.crit{border-top-color:var(--sev-crit)}  .card.crit .n{color:var(--sev-crit)}
 .card.high{border-top-color:var(--sev-high)}  .card.high .n{color:var(--sev-high)}
 .card.med{border-top-color:var(--sev-med)}    .card.med .n{color:var(--sev-med)}
 .card.low{border-top-color:var(--sev-low)}    .card.low .n{color:var(--sev-low)}
 .card.fixed{border-top-color:var(--sev-ok)}   .card.fixed .n{color:var(--sev-ok)}
 .card.vuln{border-top-color:var(--sev-high)}  .card.vuln .n{color:var(--sev-high)}
 .card.err{border-top-color:var(--sev-med)}    .card.err .n{color:var(--sev-med)}
 .card.skip{border-top-color:var(--border-strong)} .card.skip .n{color:var(--text-faint)}
 .card.new{border-top-color:var(--sev-high)}   .card.new .n{color:var(--sev-high)}
 .card.regressed{border-top-color:var(--sev-med)} .card.regressed .n{color:var(--sev-med)}
 .card.unchanged{border-top-color:var(--border-strong)} .card.unchanged .n{color:var(--text-faint)}

 /* ---- severity distribution bar ------------------------------------------ */
 .sevbar-wrap{padding:14px 28px 6px}
 .sevbar{display:flex;height:10px;border-radius:6px;overflow:hidden;
         background:var(--surface-2);border:1px solid var(--border)}
 .sevbar span{display:block;height:100%}
 .sevbar .sb-crit{background:var(--sev-crit)} .sevbar .sb-high{background:var(--sev-high)}
 .sevbar .sb-med{background:var(--sev-med)}   .sevbar .sb-low{background:var(--sev-low)}
 .sevbar-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:11.5px;color:var(--text-muted);
                margin-top:6px}
 .sevbar-legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;
                  vertical-align:-1px}
 .sevbar-legend .sb-crit{background:var(--sev-crit)} .sevbar-legend .sb-high{background:var(--sev-high)}
 .sevbar-legend .sb-med{background:var(--sev-med)}   .sevbar-legend .sb-low{background:var(--sev-low)}

 /* ---- findings toolbar ----------------------------------------------------- */
 .toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;
          margin:6px 28px 14px;padding:10px 14px;background:var(--surface);
          border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow)}
 .chips{display:flex;gap:6px;flex-wrap:wrap}
 .chip{border:1px solid var(--border-strong);background:var(--surface);color:var(--text-muted);
       border-radius:999px;padding:4px 12px;font-size:12px;font-weight:600;cursor:pointer;
       display:inline-flex;align-items:center;gap:6px;transition:background .15s,color .15s}
 .chip i{width:8px;height:8px;border-radius:50%;background:var(--dot,var(--text-faint))}
 .chip[aria-pressed="true"]{background:var(--accent-weak);color:var(--text);
                            border-color:var(--accent)}
 .chip[aria-pressed="false"]{opacity:.45}
 .chip[data-sev="critical"]{--dot:var(--sev-crit)}
 .chip[data-sev="high"]{--dot:var(--sev-high)}
 .chip[data-sev="medium"]{--dot:var(--sev-med)}
 .chip[data-sev="low"]{--dot:var(--sev-low)}
 .toolbar select,.toolbar input[type="search"]{background:var(--surface);
       color:var(--text);border:1px solid var(--border-strong);border-radius:8px;
       padding:5px 10px;font-size:12.5px;font-family:inherit}
 .toolbar input[type="search"]{min-width:200px;flex:1 1 160px}
 .toolbar .btn{border:1px solid var(--border-strong);background:var(--surface-2);
       color:var(--text-muted);border-radius:8px;padding:5px 12px;font-size:12px;
       cursor:pointer;font-family:inherit}
 .toolbar .btn:hover{color:var(--text);border-color:var(--accent)}
 .viscount{font-size:12px;color:var(--text-faint);margin-left:auto;white-space:nowrap;
           font-variant-numeric:tabular-nums}

 /* ---- copy buttons ---------------------------------------------------------- */
 .copybtn{border:1px solid var(--border-strong);background:var(--surface-2);
       color:var(--text-muted);border-radius:6px;padding:1px 8px;font-size:10.5px;
       cursor:pointer;font-family:inherit;margin-left:6px;vertical-align:1px;
       transition:color .15s,border-color .15s}
 .copybtn:hover{color:var(--text);border-color:var(--accent)}
 .copybtn.copied{color:var(--sev-ok);border-color:var(--sev-ok)}
 .copybtn.copyfail{color:var(--sev-high);border-color:var(--sev-high)}

 /* ---- tables ------------------------------------------------------------------ */
 .table-wrap{margin:0 28px 30px;background:var(--surface);border:1px solid var(--border);
       border-radius:12px;box-shadow:var(--shadow);overflow:auto;max-height:82vh}
 table{border-collapse:collapse;width:100%;background:var(--surface);font-size:12.5px}
 th,td{padding:9px 11px;border-bottom:1px solid var(--border);text-align:left;
       vertical-align:top}
 thead th{background:var(--surface-2);color:var(--text-muted);font-size:11px;
       text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;z-index:2;
       border-bottom:1px solid var(--border-strong);white-space:nowrap}
 thead th[data-key]{cursor:pointer;user-select:none}
 thead th[data-key]:hover{color:var(--text)}
 thead th .sort-ind{opacity:.35;font-size:9px;margin-left:3px}
 thead th[aria-sort] .sort-ind{opacity:1;color:var(--accent)}
 tbody tr:hover td{background:var(--surface-3)}
 tbody tr:last-child td{border-bottom:none}

 /* per-finding severity accents */
 .sev-crit td:first-child{box-shadow:inset 3px 0 0 var(--sev-crit)}
 .sev-high td:first-child{box-shadow:inset 3px 0 0 var(--sev-high)}
 .sev-med td:first-child{box-shadow:inset 3px 0 0 var(--sev-med)}
 .sev-low td:first-child{box-shadow:inset 3px 0 0 var(--sev-low)}
 .sev-cell{font-weight:600}
 .sev-crit .sev-cell{color:var(--sev-crit)}
 .sev-high .sev-cell{color:var(--sev-high)}
 .sev-med .sev-cell{color:var(--sev-med)}
 .sev-low .sev-cell{color:var(--sev-low)}

 /* evidence / cvss sub-cells */
 .evid{margin-top:4px;font-size:11px;color:var(--text-muted);line-height:1.5}
 .cvss{margin-top:3px;font-size:11px}
 .cvss b{color:var(--sev-crit)}
 .cvss code{font-size:10px}
 .comp-badges{margin-top:4px}
 .badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;
        background:var(--accent-weak);color:var(--accent);margin:1px 3px 1px 0;
        font-weight:600;letter-spacing:.2px}
 .poc code{display:block;white-space:pre-wrap;word-break:break-all;margin-bottom:4px}
 .poc details{margin-top:4px}
 .poc pre{max-height:180px}
 .shot summary{margin-top:4px}
 .shot img{margin-top:4px;border:1px solid var(--border);border-radius:6px}

 /* ---- section containers (compliance / remediation / coverage / ai) ------------ */
 section{padding:0 28px 26px}
 section h2{font-size:17px;margin:0 0 12px;font-weight:650}
 .compliance{width:100%;border-collapse:collapse;background:var(--surface);
       border:1px solid var(--border);border-radius:10px;overflow:hidden;font-size:12.5px}
 .compliance th,.compliance td{padding:7px 11px;border-bottom:1px solid var(--border)}
 .compliance thead th{position:static}

 .advice-block{background:var(--surface);border:1px solid var(--border);
       border-left:4px solid var(--accent);border-radius:10px;padding:14px 18px;
       margin-bottom:14px;box-shadow:var(--shadow)}
 .advice-block h4{margin:0 0 6px;font-size:14px}
 .advice-count{color:var(--text-faint);font-size:12px;font-weight:normal}
 .advice-headline{margin:4px 0 8px;font-size:13px}
 .advice-block p{font-size:12.5px;color:var(--text-muted);margin:6px 0}
 .advice-block pre{max-height:260px}
 .advice-block code{background:transparent;padding:0;color:inherit}
 .also-consider{margin:6px 0 0;padding-left:18px;font-size:12.5px;color:var(--text-muted)}
 .also-consider li{margin:2px 0}

 .coverage section,.coverage h2,.coverage h3{color:inherit}
 .coverage h3{font-size:13.5px;margin:16px 0 8px;color:var(--text-muted)}
 .cov-warn{border-left:4px solid var(--sev-med);padding:10px 14px;margin:10px 0;
       background:var(--sev-med-weak);border-radius:0 8px 8px 0;font-size:12.5px}
 .cov-overview{display:flex;gap:18px;align-items:center;margin-bottom:14px;
       background:var(--surface);padding:14px 18px;border-radius:10px;
       border:1px solid var(--border);box-shadow:var(--shadow);flex-wrap:wrap}
 .cov-overall{text-align:center;min-width:120px}
 .cov-overall-label{font-size:11px;color:var(--text-faint);margin-bottom:2px}
 .cov-overall-score{font-size:30px;font-weight:700;font-variant-numeric:tabular-nums}
 .cov-stats{display:flex;flex-wrap:wrap;gap:8px;font-size:12px;color:var(--text-muted)}
 .cov-stats span{background:var(--surface-2);padding:3px 9px;border-radius:6px}
 .cov-layer-table,.cov-ep-table,.param-table{width:100%;border-collapse:collapse;
       background:var(--surface);border:1px solid var(--border);border-radius:10px;
       overflow:hidden;font-size:12.5px;margin-bottom:14px}
 .cov-layer-table th,.cov-layer-table td,.cov-ep-table th,.cov-ep-table td,
 .param-table th,.param-table td{padding:6px 11px;border-bottom:1px solid var(--border)}
 .cov-layer-table th,.cov-ep-table th,.param-table th{background:var(--surface-2)}
 .phase-row td{background:var(--surface-3);font-size:11px;color:var(--text-muted)}
 .cov-bar{display:inline-block;width:80px;height:8px;background:var(--surface-2);
       border-radius:4px;vertical-align:middle;margin-right:6px;overflow:hidden}
 .cov-fill{height:100%;border-radius:4px}
 .cov-fill.cov-high{background:var(--sev-ok)} .cov-fill.cov-med{background:var(--sev-med)}
 .cov-fill.cov-low{background:var(--sev-high)}
 .cov-pct{font-size:11px;color:var(--text-muted)}
 .cov-overall-score.cov-high{color:var(--sev-ok)}
 .cov-overall-score.cov-med{color:var(--sev-med)}
 .cov-overall-score.cov-low{color:var(--sev-high)}
 .badge-crawled{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;
       background:var(--sev-low-weak);color:var(--sev-low);margin-left:4px;font-weight:600}
 .param-loc{display:inline-block;padding:0 5px;border-radius:4px;font-size:10px;
       background:var(--surface-2);color:var(--text-muted);margin-left:4px}
 .refl-yes{color:var(--sev-ok);font-weight:600}
 .refl-no{color:var(--text-faint)}
 .conf-yes{color:var(--sev-high);font-weight:600;font-size:10px}
 .param-detail{margin-bottom:10px;background:var(--surface);border:1px solid var(--border);
       border-radius:10px;box-shadow:var(--shadow)}
 .param-detail summary{padding:8px 14px;font-size:12.5px}
 .param-detail .param-table{margin:0;border-radius:0;border:none;box-shadow:none}
 .cov-help{font-size:11.5px;color:var(--text-muted);margin-top:10px;padding:12px 14px;
       background:var(--surface-3);border:1px solid var(--border);border-radius:8px;
       line-height:1.6}

 /* ---- AI narrative ------------------------------------------------------------- */
 .ai-report h2{font-size:17px;margin:0 0 12px}
 .ai-report h3{font-size:14px;margin:16px 0 6px}
 .ai-report h4{font-size:13px;margin:12px 0 5px}
 .ai-report p{font-size:13px;color:var(--text-muted);line-height:1.65;margin:8px 0}
 .ai-report ul,.ai-report ol{font-size:13px;color:var(--text-muted);padding-left:22px;margin:8px 0}
 .ai-report li{margin:3px 0}
 .ai-report blockquote{margin:8px 0;padding:8px 12px;background:var(--surface-2);
       border-left:3px solid var(--border-strong);color:var(--text-muted);font-size:12px;
       border-radius:0 8px 8px 0}
 .ai-report code{background:var(--code-bg);color:var(--code-text)}
 .ai-report table.ai-table{width:100%;margin:10px 0;border:1px solid var(--border);
       border-radius:10px;overflow:hidden}
 .ai-report table.ai-table td{padding:6px 11px;border-bottom:1px solid var(--border);
       font-size:12px;background:var(--surface)}
 .ai-report.degraded{border-left:4px solid var(--sev-med)}
 .muted{color:var(--text-faint);font-size:12px;padding:8px 0}

 /* ---- banners / verdict / misc ---------------------------------------------------- */
 .banner{margin:10px 28px 0;padding:11px 16px;border-radius:10px;font-size:13px;
       border:1px solid var(--sev-med);background:var(--sev-med-weak);color:var(--text)}
 .banner.banner-crit{border-color:var(--sev-crit);background:var(--sev-crit-weak)}
 .verdict{display:inline-block;padding:4px 14px;border-radius:8px;font-weight:700;
       font-size:13px;margin-left:12px;vertical-align:2px}
 .verdict.pass{background:var(--sev-ok-weak);color:var(--sev-ok)}
 .verdict.fail{background:var(--sev-crit-weak);color:var(--sev-crit)}
 footer{padding:16px 28px 26px;color:var(--text-faint);font-size:12px}

 /* ---- narrow screens ----------------------------------------------------------------- */
 @media (max-width:720px){
  header{padding:18px 16px 16px}
  .head-tools{top:14px;right:12px}
  .summary,.sevbar-wrap,.toolbar{padding-left:16px;padding-right:16px;margin-left:0;margin-right:0}
  .toolbar{margin:6px 16px 14px}
  .summary{padding-top:16px}
  .table-wrap{margin:0 16px 26px;max-height:none}
  section{padding:0 16px 22px}
  .banner{margin:10px 16px 0}
  .card{min-width:104px;flex:1 1 104px;padding:12px 14px}
  .card .n{font-size:24px}
 }

 /* ---- print -------------------------------------------------------------------------- */
 @media print{
  body{background:#fff;color:#111}
  .toolbar,.head-tools,.copybtn{display:none!important}
  .table-wrap{max-height:none;overflow:visible;border:none;margin:0 12px 20px;
               box-shadow:none}
  thead th{position:static;background:#f0f2f7!important;color:#111!important;
           -webkit-print-color-adjust:exact;print-color-adjust:exact}
  section,footer{page-break-inside:avoid}
  .card,.advice-block,.cov-overview{box-shadow:none;-webkit-print-color-adjust:exact;
                                    print-color-adjust:exact}
  a{color:#111;text-decoration:none}
 }
 @media (prefers-reduced-motion: reduce){
  *{transition:none!important}
 }
"""

# ---------------------------------------------------------------------------
# Theme boot: runs in <head> BEFORE the stylesheet paints, so the first frame
# is already the right theme (no white flash for dark-mode readers).  Tries
# the persisted choice first, then the OS preference; file:// pages keep
# localStorage per-directory, and every failure mode degrades to light.
# ---------------------------------------------------------------------------

_BOOT_JS = (
    '<script>(function(){try{var t=localStorage.getItem("xss-theme");'
    'if(t!=="dark"&&t!=="light"){t=window.matchMedia&&'
    'matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";}'
    'document.documentElement.dataset.theme=t;}catch(e){}})();</script>'
)


def theme_boot_script() -> str:
    """Inline <head> snippet that pins ``data-theme`` before first paint."""
    return _BOOT_JS


def theme_toggle_button() -> str:
    """Header button the interactive script wires up.  Pure HTML -- inert
    without JS, which is exactly the no-JS contract of this module."""
    return (
        '<button id="themeToggle" class="btn" type="button" '
        'aria-label="Toggle dark mode" title="Toggle dark mode">'
        '<span aria-hidden="true">&#9789;</span></button>'
    )


# Inline brand mark (shield + check) -- pure SVG so every report keeps the
# zero-dependency guarantee; currentColor picks up the header theme.
BRAND_SVG = (
    '<svg class="brandmark" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
    '<path d="M12 2l8 3.5v5.4c0 5-3.4 9.6-8 11.1-4.6-1.5-8-6.1-8-11.1V5.5L12 2z" '
    'stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>'
    '<path d="M8.5 12.2l2.4 2.4 4.6-5" stroke="currentColor" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>')


_THEME_TOGGLE_JS = """
 var _root=document.documentElement,_btn=document.getElementById("themeToggle");
 if(_btn){_btn.addEventListener("click",function(){
   var t=_root.dataset.theme==="dark"?"light":"dark";
   _root.dataset.theme=t;
   try{localStorage.setItem("xss-theme",t);}catch(e){}
 });}
"""

_FINDINGS_JS = """
 var _rows=[].slice.call(document.querySelectorAll("tbody tr[data-sev]"));
 if(_rows.length){
  var _state={sev:{},q:"",type:""};
  var _box=document.getElementById("searchBox"),
      _sel=document.getElementById("typeFilter"),
      _cnt=document.getElementById("visCount"),
      _reset=document.getElementById("resetFilters");
  var _chips=[].slice.call(document.querySelectorAll(".chip[data-sev]"));
  _chips.forEach(function(c){_state.sev[c.dataset.sev]=true;});

  function _apply(){
    var shown=0;
    _rows.forEach(function(tr){
      var ok=true;
      var anyOff=_chips.some(function(c){return !_state.sev[c.dataset.sev];});
      if(anyOff){
        var s=tr.dataset.sev;
        ok=(s in _state.sev)?_state.sev[s]:true;
      }
      if(ok&&_state.type&&tr.dataset.type!==_state.type)ok=false;
      if(ok&&_state.q&&tr.textContent.toLowerCase().indexOf(_state.q)<0)ok=false;
      tr.hidden=!ok;
      if(ok)shown++;
    });
    if(_cnt)_cnt.textContent="showing "+shown+" of "+_rows.length;
  }
  _chips.forEach(function(c){
    c.setAttribute("aria-pressed","true");
    c.addEventListener("click",function(){
      _state.sev[c.dataset.sev]=!_state.sev[c.dataset.sev];
      c.setAttribute("aria-pressed",_state.sev[c.dataset.sev]?"true":"false");
      _apply();
    });
  });
  if(_sel)_sel.addEventListener("change",function(){_state.type=_sel.value;_apply();});
  if(_box)_box.addEventListener("input",function(){
    _state.q=_box.value.trim().toLowerCase();_apply();});
  if(_reset)_reset.addEventListener("click",function(){
    _state.q="";_state.type="";if(_box)_box.value="";if(_sel)_sel.value="";
    _chips.forEach(function(c){_state.sev[c.dataset.sev]=true;
      c.setAttribute("aria-pressed","true");});
    _apply();});

  /* column sorting: numeric when both cells carry data-val, else text */
  var _tb=_rows[0].parentNode;
  [].slice.call(document.querySelectorAll("thead th[data-key]")).forEach(function(th){
    var ind=document.createElement("span");
    ind.className="sort-ind";ind.textContent="\\u2195";th.appendChild(ind);
    th.addEventListener("click",function(){
      var dir=th.getAttribute("aria-sort")==="ascending"?"descending":"ascending";
      [].slice.call(th.parentNode.children).forEach(function(h){
        h.removeAttribute("aria-sort");
        var si=h.querySelector(".sort-ind");if(si)si.textContent="\\u2195";});
      th.setAttribute("aria-sort",dir);
      ind.textContent=dir==="ascending"?"\\u2191":"\\u2193";
      var idx=th.cellIndex;
      _rows.sort(function(a,b){
        var ca=a.children[idx],cb=b.children[idx];
        if(!ca||!cb)return 0;
        var va=ca.getAttribute("data-val"),vb=cb.getAttribute("data-val");
        if(va!==null&&vb!==null&&va!==""&&vb!==""){
          va=parseFloat(va);vb=parseFloat(vb);
          return dir==="ascending"?va-vb:vb-va;
        }
        va=ca.textContent.trim().toLowerCase();
        vb=cb.textContent.trim().toLowerCase();
        var r=va<vb?-1:va>vb?1:0;
        return dir==="ascending"?r:-r;
      });
      _rows.forEach(function(tr){_tb.appendChild(tr);});
    });
  });
  _apply();
 }

 /* copy-to-clipboard: button carries data-copy="<element id>" */
 [].slice.call(document.querySelectorAll(".copybtn[data-copy]")).forEach(function(b){
   b.addEventListener("click",function(){
     var el=document.getElementById(b.dataset.copy);
     var t=el?el.textContent:"";
     function done(ok){
       var old=b.textContent;
       b.textContent=ok?"copied":"failed";
       b.classList.add(ok?"copied":"copyfail");
       setTimeout(function(){b.textContent=old;
         b.classList.remove("copied","copyfail");},1200);
     }
     function fallback(){
       try{
         var ta=document.createElement("textarea");
         ta.value=t;ta.style.position="fixed";ta.style.opacity="0";
         document.body.appendChild(ta);ta.select();
         done(document.execCommand("copy"));
         document.body.removeChild(ta);
       }catch(e){done(false);}
     }
     if(navigator.clipboard&&navigator.clipboard.writeText){
       navigator.clipboard.writeText(t).then(function(){done(true);},fallback);
     }else fallback();
   });
 });

 /* print: expand every <details> (PoC HTML, screenshots, advice code) so the
    paper copy carries the evidence, then restore on return. */
 var _collapsed=[];
 window.addEventListener("beforeprint",function(){
   _collapsed=[].slice.call(document.querySelectorAll("details:not([open])"));
   _collapsed.forEach(function(d){d.setAttribute("open","");});
 });
 window.addEventListener("afterprint",function(){
   _collapsed.forEach(function(d){d.removeAttribute("open");});
   _collapsed=[];
 });
"""


def interactive_js() -> str:
    """One defensive script shared by every report page.  Null-guarded
    throughout: a page without a toolbar, without copy buttons, or without
    tables simply no-ops the corresponding block.  The script never touches
    report data -- filtering reads ``textContent`` of already-escaped markup
    and sorting/copying only rearrange or read existing DOM nodes."""
    return ("<script>(function(){\"use strict\";"
            + _THEME_TOGGLE_JS + _FINDINGS_JS + "})();</script>")
