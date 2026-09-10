# Cross-tool XSS comparison (third-party corpus)

Generated: 2026-09-10 21:41:22  
Targets: http://127.0.0.1:8896  
Cases: 18 (same targets for every tool)

| tool | TP | FP | TN | FN | errors | time (s) |
|---|---|---|---|---|---|---|
| XSSentinel | 12 | 0 | 6 | 0 | 0 | 30.5 |
| nuclei-dast-xss | 11 | 1 | 5 | 1 | 0 | 13.7 |

## Per-case matrix

| case | ground truth | XSSentinel | nuclei-dast-xss |
|---|---|---|---|
| pos-elem-01 | vulnerable | yes | yes |
| pos-attr-01 | vulnerable | yes | yes |
| pos-attr-05 | vulnerable | yes | yes |
| pos-script-01 | vulnerable | yes | yes |
| pos-script-03 | vulnerable | yes | yes |
| pos-comment-01 | vulnerable | yes | yes |
| pos-url-01 | vulnerable | yes | yes |
| pos-dom-01 | vulnerable | yes | no ! |
| pos-svg-01 | vulnerable | yes | yes |
| pos-polyglot-01 | vulnerable | yes | yes |
| neg-rcdata-01 | vulnerable | yes | yes |
| neg-filter-01 | vulnerable | yes | yes |
| neg-escape-01 | safe | no | no |
| neg-comment-01 | safe | no | no |
| neg-attr-01 | safe | no | no |
| neg-csp-01 | safe | no | yes ! |
| neg-jsonp-01 | safe | no | no |
| neg-rcdata-05 | safe | no | no |

## Disagreements with ground truth

- `pos-dom-01`: **nuclei-dast-xss** missed-a-real-XSS
- `neg-csp-01`: **nuclei-dast-xss** false-positive