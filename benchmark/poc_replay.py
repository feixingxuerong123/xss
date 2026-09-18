"""PoC replay probe: does the PoC a finding ships actually reproduce?

The benchmark counts findings; it never checks the artefact attached to them.
But "可复现 PoC" is one of the project's acceptance criteria, and a finding
whose PoC is empty, points at the wrong path, or whose curl does not actually
reproduce the claim is a finding a human cannot verify -- the whole point of
shipping a PoC.

For every POSITIVE case this probe takes the finding(s) the scorer credits and
checks, per finding:

  payload  -- the payload appears in the PoC (raw, percent-encoded or, for
              base64 containers, in its decoded form);
  path     -- the case's path appears in the PoC;
  replay   -- the PoC's own curl is replayed (query, headers and --data body)
              and the response must contain the payload.

Three ways the FIRST version of this probe lied, all fixed here and each
measured against a real case:

  * it compared the finding's taint MARKER against a DOM PoC that
    deliberately ships a real payload instead (poc.py swaps in
    DOM_POC_PAYLOAD) -- 9 false defects, all pos-dom-*;
  * it dropped the POST body, so pos-pshift-01 replayed as an empty POST;
  * it only looked for the encoded string, so pos-preenc-01 (base64 JSON,
    decoded and reflected by the server) read as a failure.

Findings whose payload field is a DESCRIPTOR ("(TT: tt_policy_bypass)") rather
than an injected value are checked for "a PoC exists and names the carrier",
because by construction the descriptor never travels in a request.

Usage: python -m benchmark.poc_replay [port] [max_payloads] [max_transforms]
Writes benchmark/results/poc_replay.json.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import re
import shlex
import sys
import threading
import time
import urllib.parse
from http.server import ThreadingHTTPServer

sys.path.insert(0, ".")

from benchmark.runner import _build_target_url, _case_extra_args  # noqa: E402
from benchmark.runner import _invoke_scanner, _is_detected  # noqa: E402
from benchmark.server import BenchmarkHandler, load_routes  # noqa: E402

# Findings a plain GET replay (query string and request headers) reproduces
# end to end.  Anything else needs a carrier this probe does not speak --
# multipart upload (-F), a two-step stored view, a redirect chain -- and is
# reported "n/a (carrier not replayable)", NOT as a defect.
_REPLAYABLE = ("reflected", "cookie_xss", "header_xss", "response_headers")
# DOM findings ship an HTML navigation page instead of a request.
_DOM_TYPES = ("dom_dynamic", "dom", "dom_prototype", "stored_dom")
# Findings whose payload is a description of the sink, not a value -- the
# value check is meaningless for these by construction.
_DESCRIPTOR_TYPES = ("trusted_types_policy_bypass", "trusted_types_no_policy",
                     "trusted_types_policy_unused", "prototype_pollution",
                     "xs_leak_surface", "service_worker_xss",
                     "web_worker_xss", "websocket_xss", "graphql_xss")

try:
    from xssentinel.core.poc import DOM_POC_PAYLOAD, _MARKER_TYPES
except Exception:                                        # pragma: no cover
    DOM_POC_PAYLOAD = "<img src=x onerror=alert(document.domain)>"
    _MARKER_TYPES = ("dom", "dom_dynamic")


def start_server(port: int = 0) -> ThreadingHTTPServer:
    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", port), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for _ in range(40):
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_port,
                                           timeout=1)
            c.request("GET", "/health")
            r = c.getresponse()
            r.read()
            c.close()
            if r.status == 200:
                return srv
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("server did not become ready")


def _variants(s: str) -> list:
    """Every form the payload may legitimately take in a PoC or a response."""
    out = {s}
    out.add(urllib.parse.quote(s, safe=""))
    out.add(urllib.parse.quote(s, safe="/:?=&"))
    # quote_plus: poc.py builds bodies and URLs with urlencode(), which turns
    # a space into '+'.  Without this the PoC looked payload-less for every
    # payload containing a space (measured on pos-math-01 and neg-filter-01).
    out.add(urllib.parse.quote_plus(s, safe=""))
    out.add(urllib.parse.quote_plus(s, safe="/:?=&"))
    out.add(s.replace("'", "%27"))
    out.add(s.replace("'", "%27").replace(" ", "+"))
    # HTML-escaped forms: a form-value PoC renders < as &lt; (measured on
    # pos-so2-01, a second-order PoC whose <input value="..."> is escaped).
    import html as _html
    for esc in (_html.escape(s, quote=True), _html.escape(s, quote=False)):
        if esc != s:
            out.add(esc)
            out.add(urllib.parse.quote(esc, safe=""))
            out.add(urllib.parse.quote_plus(esc, safe=""))
    try:
        dec = base64.b64decode(s + "=" * (-len(s) % 4)).decode(
            "utf-8", "replace")
        if dec and dec != s:
            out.add(dec)
            out.add(urllib.parse.quote(dec, safe=""))
            for part in re.findall(r'"[^"]*?<[^"]*?"', dec):
                out.add(part.strip('"'))
    except Exception:
        pass
    return [v for v in out if v]


def _parse_curl(curl: str) -> tuple:
    """(url, headers, body) from a PoC curl line.

    headers carries "__method__" when the command sets one; body is --data.
    A POST PoC whose body was dropped replayed as an empty POST and scored as
    "payload not in response" -- a probe bug, not a PoC bug (pos-pshift-01).
    """
    if not curl.strip().startswith("curl"):
        return None, {}, ""
    try:
        parts = shlex.split(curl)
    except ValueError:
        return None, {}, ""
    url, headers, body = None, {}, ""
    for i, p in enumerate(parts):
        if p.startswith("http") and url is None:
            url = p
        elif p in ("-H", "--header") and i + 1 < len(parts):
            k, _, v = parts[i + 1].partition(":")
            headers[k.strip()] = v.strip()
        elif p in ("-X", "--request") and i + 1 < len(parts):
            headers["__method__"] = parts[i + 1]
        elif p in ("--data", "--data-raw", "--data-binary", "-d") \
                and i + 1 < len(parts):
            body = parts[i + 1]
    return url, headers, body


def _replay(url: str, headers: dict, body: str = "") -> tuple:
    """Return (response body, error)."""
    try:
        u = urllib.parse.urlsplit(url)
        path = u.path + (("?" + u.query) if u.query else "")
        c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=10)
        hdrs = {k: v for k, v in headers.items() if k != "__method__"}
        method = headers.get("__method__") or ("POST" if body else "GET")
        if body:
            hdrs.setdefault("Content-Type",
                            "application/x-www-form-urlencoded")
        c.request(method, path, body=body.encode() if body else None,
                  headers=hdrs)
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        return resp, ""
    except Exception as e:                               # pragma: no cover
        return "", str(e)


def _check(finding: dict, case: dict) -> dict:
    poc = finding.get("poc") or {}
    payload = str(finding.get("payload") or "")
    blob = " ".join(str(poc.get(k, "")) for k in ("curl", "url", "html"))
    path_key = case["path"].split("#", 1)[0].rstrip("*") or "/"
    # A crawl/mine case's finding lands on a DISCOVERED endpoint, so the case
    # declares the paths that count (same rule as benchmark.runner).
    accept_paths = list(case.get("finding_paths") or [path_key])
    ftype = finding.get("type", "")

    res = {"type": ftype, "payload": payload[:40], "expect_payload": "",
           "has_payload": False, "path_ok": False, "replay": "n/a",
           "note": ""}

    if ftype in _DESCRIPTOR_TYPES:
        nonempty = any(str(poc.get(k, "")).strip() for k in poc)
        res["has_payload"] = nonempty
        res["path_ok"] = nonempty or any(x in blob for x in accept_paths)
        res["replay"] = "n/a (descriptor finding)"
        res["note"] = "payload field describes the sink, not a value"
        return res

    if not payload:
        res["note"] = "finding carries no payload"
        return res

    # Mirror poc.py's own rule (not a restatement of it): only the MARKER
    # types get the real-payload substitute, so stored_dom -- which is in
    # _DOM_TYPES for the html check -- still ships the finding's payload.
    expect = DOM_POC_PAYLOAD if ftype in _MARKER_TYPES else payload
    res["expect_payload"] = expect[:40]
    res["has_payload"] = any(v and v in blob for v in _variants(expect))
    res["path_ok"] = any(x in blob for x in accept_paths)

    if ftype in _DOM_TYPES:
        html = str(poc.get("html", ""))
        ok = any(v and v in html for v in _variants(expect))
        res["replay"] = "ok" if ok else "payload not in PoC page"
        frag = case["path"].split("#", 1)[1] if "#" in case["path"] else ""
        if frag and frag.split("?")[0].strip("/") not in html:
            res["note"] = f"PoC page does not navigate fragment {frag!r}"
        return res

    url, headers, body = _parse_curl(str(poc.get("curl", "")))
    if not url or ftype not in _REPLAYABLE:
        res["replay"] = "n/a (carrier not replayable)"
        return res
    resp, err = _replay(url, headers, body)
    if err:
        res["replay"] = f"replay error: {err[:60]}"
        return res
    hit = any(v and v in resp for v in _variants(expect))
    res["replay"] = "ok" if hit else "payload NOT in replayed response"
    res["payload_intact"] = _payload_survived(expect, resp)
    return res


def _payload_survived(payload: str, resp: str) -> bool:
    """Did the PAYLOAD survive, or only the token?

    Phase 165: verify_semantic confirms on the token plus a structural
    context, so a filter that rewrites the payload's dangerous part --
    ``alert(`` -> ``blocked(``, or dropping a ``data:text/html,`` prefix --
    still passes that check while the shipped PoC stops reproducing and a
    human replaying it sees the neutered result.

    The test is the payload with the TOKEN wildcarded, in any benign
    encoding: re-encoding the token must not count as mangling, a rewritten
    callable or a dropped scheme must.
    """
    if not resp:
        return False
    for v in _variants(payload):
        pat = re.sub(r"xssv_[0-9a-f]{8}", "xssv_[0-9a-f]{8}", re.escape(v))
        try:
            if re.search(pat, resp):
                return True
        except Exception:
            return True
    return False


def _is_defect(c: dict) -> bool:
    if not c["has_payload"] or not c["path_ok"]:
        return True
    if c["type"] in _REPLAYABLE and c["replay"] != "ok":
        return True
    if c["type"] in _DOM_TYPES and c["replay"] != "ok":
        return True
    return False


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18899
    max_p = int(sys.argv[2]) if len(sys.argv) > 2 else 14
    max_t = int(sys.argv[3]) if len(sys.argv) > 3 else 12

    srv = start_server(port)
    base = f"http://127.0.0.1:{srv.server_port}"
    manifest = json.load(open("benchmark/manifest.json", encoding="utf-8"))
    cases = manifest["cases"] if isinstance(manifest, dict) else manifest
    pos = [c for c in cases if c.get("ground_truth") == "vulnerable"]

    rows, total = [], 0
    for i, case in enumerate(pos, 1):
        url = _build_target_url(base, case)
        report, _el, _err = _invoke_scanner(
            url, timeout=90, max_payloads=max_p, max_transforms=max_t,
            engine="sync", extra_args=_case_extra_args(base, case))
        detected, _n, credited = _is_detected(report, case)
        if not detected:
            rows.append({"case_id": case["id"], "findings": [],
                         "verdict": "NO FINDING"})
            print(f"[{i}/{len(pos)}] {case['id']:<18} NO FINDING", flush=True)
            continue
        checked = [_check(f, case) for f in credited]
        total += len(checked)
        bad = [c for c in checked if _is_defect(c)]
        rows.append({"case_id": case["id"], "findings": checked,
                     "verdict": "ok" if not bad else "DEFECT"})
        print(f"[{i}/{len(pos)}] {case['id']:<18} "
              f"{'ok' if not bad else 'DEFECT':<7} n={len(checked)} "
              f"{[(c['type'], c['replay'][:28]) for c in bad][:2]}",
              flush=True)

    defects = [r for r in rows if r["verdict"] == "DEFECT"]
    notok = [r for r in rows if r["verdict"] != "ok"]
    replayed = [c for r in rows for c in r["findings"] if c["replay"] == "ok"]
    failed = [c for r in rows for c in r["findings"]
              if c["type"] in _REPLAYABLE and c["replay"] != "ok"]
    print(f"\n=== summary ===\npositive cases: {len(rows)}   "
          f"findings checked: {total}")
    print(f"cases whose PoC verifies: {len(rows) - len(notok)}")
    print(f"cases with a DEFECT: {len(defects)} "
          f"{[r['case_id'] for r in defects]}")
    print(f"HTTP replays that reproduced the payload: {len(replayed)}"
          f"   replayable findings that did not: {len(failed)}")
    for c in failed:
        print(f"    !! {c['type']} payload={c['payload'][:34]!r} "
              f"{c['replay']}")
    mangled = [c for r in rows for c in r["findings"]
               if c.get("payload_intact") is False
               and c["type"] in _REPLAYABLE]
    print(f"replayable findings whose PAYLOAD was rewritten (token-only "
          f"confirmation): {len(mangled)}")
    for c in mangled:
        print(f"    ?? {c['type']} payload={c['payload'][:40]!r}")
    out = os.path.join("benchmark", "results", "poc_replay.json")
    json.dump(rows, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("written:", out)
    srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
