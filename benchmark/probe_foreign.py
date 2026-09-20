"""Ad-hoc probe: where does Chromium actually put a node that breaks out of
foreign content?  Answers the tokenizer/tree-construction questions the HTML
spec is too easy to misremember -- the sandbox's foreign-content rules are
written from these answers, not from memory.

Usage: python -m benchmark.probe_foreign
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")

X = "__x()"

CASES = {
    "svg_style_img": f'<svg><style><img src=x onerror="{X}"></style></svg>',
    "svg_div_img": f'<svg><div><img src=x onerror="{X}"></div></svg>',
    "svg_img_bare": f'<svg><img src=x onerror="{X}"></svg>',
    "svg_span_img": f'<svg><span><img src=x onerror="{X}"></span></svg>',
    "math_style_img": f'<math><style><img src=x onerror="{X}"></style></math>',
    "math_mi_img": f'<math><mi><img src=x onerror="{X}"></mi></math>',
    "svg_title_img": f'<svg><title><img src=x onerror="{X}"></title></svg>',
    "svg_desc_img": f'<svg><desc><img src=x onerror="{X}"></desc></svg>',
    "svg_fo_div": f'<svg><foreignObject><div onclick="{X}">y</div></foreignObject></svg>',
    "svg_p_style": f'<svg></p><style><a id="</style><img src=x onerror={X}>">',
    "svg_table_td": f'<svg><table><td><img src=x onerror={X}></td></table></svg>',
    "svg_script": f'<svg><script>{X}</script></svg>',
    "svg_style_close_in": '<svg><style>x</style><img src=x onerror=' + X + '></svg>',
    "noscript_p_title":
        f'<noscript><p title="</noscript><img src=x onerror={X}>">',
    "xmp_noscript": f'<xmp><noscript></xmp><img src=x onerror={X}>',
    "select_style": f'<select><option><style></option></select>'
                    f'<img src=x onerror={X}></style></select>',
    "form_math_mtext": f'<form><math><mtext></form><form><mglyph><style>'
                       f'</style><img src=x onerror={X}>',
    "template_script": f'<template><script>{X}</script></template>',
    "table_caption_svg": f'<table><tr><td><svg><style>'
                         f'<img src=x onerror="{X}"></style></svg></td></tr></table>',
    "svg_text_img": f'<svg><text><img src=x onerror="{X}"></text></svg>',
}

JS = """
(o) => {
  const rows = [];
  const walk = (n, d, path) => {
    let label;
    if (n.nodeType === 1) {
      const ns = (n.namespaceURI || '').split('/').pop();
      label = n.tagName.toLowerCase() + '{' + ns + '}';
      for (const a of n.attributes) label += ' @' + a.name;
    } else if (n.nodeType === 3) {
      label = 'TEXT ' + JSON.stringify(n.data.slice(0, 20));
    } else {
      label = 'NODE' + n.nodeType;
    }
    rows.push(d + ' ' + path + ' :: ' + label);
    let i = 0;
    for (const c of n.childNodes) walk(c, d + 1, path + '/' + (i++));
  };
  const c = document.createElement('div');
  c.innerHTML = o.f;
  walk(c, 0, '');
  return {ser: c.innerHTML, rows: rows};
}
"""


def main() -> int:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page()
        pg.goto("about:blank")
        for k, v in CASES.items():
            r = pg.evaluate(JS, {"f": v})
            print(f"\n--- {k}")
            print(f"  src: {v[:120]}")
            print(f"  ser: {r['ser'][:130]}")
            for line in r["rows"][:12]:
                print(f"     {line}")
        b.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
