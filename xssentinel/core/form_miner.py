"""HTML form miner.

Discovers <form> elements on a page, classifies them (GET/POST, action URL,
fields), and produces a list of (url, method, params, data) tuples ready
to feed into the scanner.  Also auto-fills hidden/empty fields with test
markers so the scanner can probe every field without manual setup.

Form field handling:
  * <input type=text/email/search/url/tel/password>  -> text field
  * <input type=hidden>                              -> keep server value
  * <input type=checkbox/radio>                      -> use 'on' if checked
  * <textarea>                                       -> text field
  * <select>                                         -> first <option> value
  * Fields with no name                              -> skipped
"""
from __future__ import annotations
import re
from urllib.parse import urljoin

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False

from .parser_utils import bs_parser as _bs_parser

# Default test value for empty text fields.  Includes a marker so the
# scanner can later verify reflection.
from .stealth import marker as _marker
DEFAULT_TEXT_VALUE = "xssentinel_test"


def _text_value() -> str:
    """Lazy: honors --marker-prefix set after import."""
    return _marker("xssentinel_test")


# Regex fallback when bs4 isn't available.
FORM_RE = re.compile(
    r'<form\b([^>]*)>(.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)
INPUT_RE = re.compile(
    r'<input\b([^>]*)/?>',
    re.IGNORECASE,
)


def _parse_attrs(attr_str: str) -> dict:
    """Parse a tag's attribute string into a dict (regex fallback)."""
    attrs = {}
    for m in re.finditer(
        r'(\w[\w-]*)\s*=\s*"([^"]*)"|(\w[\w-]*)\s*=\s*\'([^\']*)\'|(\w[\w-]*)',
        attr_str,
    ):
        if m.group(1):
            attrs[m.group(1).lower()] = m.group(2)
        elif m.group(3):
            attrs[m.group(3).lower()] = m.group(4)
        elif m.group(5):
            attrs[m.group(5).lower()] = ""
    return attrs


def extract_forms(html: str, base_url: str) -> list[dict]:
    """Extract all forms from an HTML page.

    Returns a list of form dicts:
        {
            "action": str,    # resolved absolute URL
            "method": str,    # "GET" or "POST"
            "fields": list[dict],  # [{name, type, value}, ...]
        }
    """
    if not html:
        return []

    forms = []
    if _HAS_BS4:
        soup = BeautifulSoup(html, _bs_parser())
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "GET") or "GET").upper()
            action_url = urljoin(base_url, action) if action else base_url
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                tag = inp.name.lower()
                if tag == "textarea":
                    val = inp.string or inp.get("value", "")
                    fields.append({"name": name, "type": "text", "value": val})
                elif tag == "select":
                    opt = inp.find("option")
                    val = opt.get("value", "") if opt else ""
                    fields.append({"name": name, "type": "select", "value": val})
                else:  # input
                    itype = (inp.get("type", "text") or "text").lower()
                    val = inp.get("value", "")
                    fields.append({"name": name, "type": itype, "value": val})
            forms.append({
                "action": action_url,
                "method": method,
                "fields": fields,
            })
    else:
        # Regex fallback
        for fm in FORM_RE.finditer(html):
            attrs = _parse_attrs(fm.group(1))
            action = attrs.get("action", "")
            method = (attrs.get("method", "GET") or "GET").upper()
            action_url = urljoin(base_url, action) if action else base_url
            fields = []
            for im in INPUT_RE.finditer(fm.group(2)):
                iattrs = _parse_attrs(im.group(1))
                name = iattrs.get("name")
                if not name:
                    continue
                itype = (iattrs.get("type", "text") or "text").lower()
                val = iattrs.get("value", "")
                fields.append({"name": name, "type": itype, "value": val})
            forms.append({
                "action": action_url,
                "method": method,
                "fields": fields,
            })
    return forms


def fill_form(form: dict, marker: str | None = None) -> tuple[dict, dict]:
    """Fill a form's fields with test values.

    Returns (params, data) suitable for the scanner:
      - GET form: params dict, data = {}
      - POST form: params = {}, data dict
    """
    params, data = {}, {}
    is_post = form["method"].upper() == "POST"
    for f in form["fields"]:
        name = f["name"]
        ftype = f["type"].lower()
        if ftype in ("hidden", "submit", "image", "button"):
            val = f["value"] or marker   # keep server-provided hidden value
        elif ftype in ("checkbox", "radio"):
            val = f["value"] or "on"
        elif ftype == "select":
            val = f["value"] or "1"
        else:  # text, email, search, password, etc.
            val = f["value"] or marker
        if is_post:
            data[name] = val
        else:
            params[name] = val
    return params, data


def forms_to_endpoints(html: str, base_url: str,
                       marker: str = DEFAULT_TEXT_VALUE
                       ) -> list[tuple[str, str, dict, dict]]:
    """Discover forms and produce (url, method, params, data) tuples.

    Each tuple is ready to pass to scanner.scan_target().
    """
    out = []
    for form in extract_forms(html, base_url):
        params, data = fill_form(form, marker)
        out.append((form["action"], form["method"], params, data))
    return out
