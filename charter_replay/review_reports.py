"""Pure offline HTML and bounded PR views of a validated replay report."""

from __future__ import annotations

import base64
import hashlib
import html
import unicodedata
from typing import Any
from urllib.parse import urlsplit

from charter_replay.compare import DIFF_CLASSES
from charter_replay.metrics import _generated, score_labels

COMMENT_LIMIT_BYTES = 16_000
REPORT_FILES = (
    "run-manifest.json",
    "report.json",
    "report.md",
    "report.html",
    "pr-comment.md",
    "pr-comment-aggregate.md",
)

_STYLE = """
:root { color-scheme: light; font: 16px/1.55 system-ui, sans-serif;
  color: #172337; background: #f4f6f9; }
* { box-sizing: border-box; }
body { margin: 0; }
main { max-width: 1440px; margin: auto; padding: 32px; }
h1 { font-size: clamp(1.8rem, 4vw, 2.8rem); line-height: 1.15; margin: 8px 0; }
h2 { font-size: 1.25rem; margin-top: 32px; }
p { max-width: 85ch; }
.eyebrow { font-size: .8rem; letter-spacing: .14em; text-transform: uppercase; }
.muted { color: #506078; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px; margin: 24px 0; }
.card, .panel { background: #fff; border: 1px solid #d5dce5; border-radius: 10px; }
.card { padding: 16px; }
.card strong { display: block; font-size: 1.6rem; }
.gate-pass { border-top: 5px solid #287453; }
.gate-fail { border-top: 5px solid #b34525; }
.gate-error { border-top: 5px solid #963756; }
.panel { padding: 20px; }
.filters { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px; }
label { display: block; font-size: .85rem; font-weight: 600; }
select, input, button { font: inherit; width: 100%; padding: 8px;
  background: #fff; color: inherit; border: 1px solid #8b98aa; border-radius: 5px; }
button { cursor: pointer; }
:focus-visible { outline: 3px solid #316dc1; outline-offset: 3px; }
.table-wrap { overflow-x: auto; background: #fff; border: 1px solid #d5dce5;
  border-radius: 8px; }
table { border-collapse: collapse; width: 100%; text-align: left; font-size: .88rem; }
th, td { padding: 12px; border-bottom: 1px solid #dce2ea; vertical-align: top; }
th { background: #e9eef5; white-space: nowrap; }
.case-table { min-width: 860px; table-layout: fixed; }
.case-table th:nth-child(1) { width: 19%; }
.case-table th:nth-child(2) { width: 32%; }
.case-table th:nth-child(5) { width: 17%; }
code, pre { font: .86rem/1.5 ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }
pre { margin: 8px 0 0; }
.badge { font-weight: 700; }
small { display: block; overflow-wrap: anywhere; }
summary { cursor: pointer; margin-top: 8px; }
a { color: #215aa1; }
[hidden] { display: none !important; }
footer { padding-top: 24px; font-size: .85rem; }
@media (max-width: 600px) { main { padding: 16px; } .panel { padding: 14px; } }
@media print { :root { background: #fff; } main { padding: 0; }
  .filters, #filters { display: none; } .table-wrap { overflow: visible; }
  .case-table { min-width: 0; } }
"""

_SCRIPT = """
'use strict';
const rows = Array.from(document.querySelectorAll('[data-case]'));
const fields = ['class', 'family', 'baseline', 'candidate', 'diff', 'origin'];
const search = document.getElementById('search');
const status = document.getElementById('visible-count');
function update() {
  const query = search.value.toLocaleLowerCase();
  let visible = 0;
  for (const row of rows) {
    const match = fields.every(key => {
      const value = document.getElementById('filter-' + key).value;
      return value === '' || row.dataset[key] === value;
    }) && row.textContent.toLocaleLowerCase().includes(query);
    row.hidden = !match;
    if (match) visible += 1;
  }
  status.textContent = visible + ' of ' + rows.length + ' cases shown';
}
for (const key of fields) {
  document.getElementById('filter-' + key).addEventListener('change', update);
}
search.addEventListener('input', update);
document.getElementById('reset').addEventListener('click', () => {
  for (const key of fields) document.getElementById('filter-' + key).value = '';
  search.value = '';
  update();
});
document.getElementById('filters').hidden = false;
update();
"""


def display_text(value: object) -> str:
    """Make control, surrogate and directional-format characters visible."""
    parts = []
    for character in str(value):
        if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            code = ord(character)
            parts.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            parts.append(character)
    return "".join(parts)


def _html(value: object) -> str:
    return html.escape(display_text(value), quote=True)


def markdown_literal(value: object) -> str:
    """Neutralize Markdown syntax and mentions as well as HTML markup."""
    text = display_text(value)
    encoded = "".join(
        character if character.isalnum() or character == " " else f"&#{ord(character)};"
        for character in text
    )
    return f"<code>{encoded}</code>"


def _status(report: dict[str, Any]) -> str:
    status = report["gate"]["status"]
    if status not in ("pass", "fail", "error"):
        raise ValueError("review rendering requires a validated gate status")
    return status


def _priority(row: dict[str, Any]) -> int:
    classification = row["classification"]
    label = (row.get("case") or {}).get("case_class")
    if classification == "newly-allowed" and label == "dangerous":
        return 0
    if classification == "newly-indeterminate":
        return 1
    return 3 if classification == "unchanged" else 2


def _attributes(row: dict[str, Any]) -> dict[str, str]:
    case = row.get("case") or {}
    return {
        "class": case.get("case_class", "unlabelled"),
        "family": case.get("case_family", "unlabelled"),
        "baseline": row["baseline"]["effect"],
        "candidate": row["candidate"]["effect"],
        "diff": row["classification"],
        "origin": "generated-variant" if _generated(row) else "seed",
    }


def _score_table(report: dict[str, Any]) -> str:
    scores = score_labels(report)
    lines = [
        '<div class="table-wrap"><table><thead><tr><th>Group</th><th>Side</th>',
        "<th>Label</th><th>Disagreement / all</th><th>Rate</th>",
        "<th>Indeterminate</th><th>Decision coverage</th></tr></thead><tbody>",
    ]
    for group, stratum in scores["strata"].items():
        if not stratum["events"] and group != "all":
            continue
        for side in ("baseline", "candidate"):
            for label in ("dangerous", "benign"):
                row = stratum[side][label]
                rate = row["disagreement_rate"]
                coverage = row["decision_coverage"]
                cells = (
                    group,
                    side,
                    label,
                    f"{row['disagreement_count']} / {row['total']}",
                    "n/a" if rate is None else f"{rate:.2%}",
                    row["effects"]["indeterminate"],
                    "n/a" if coverage is None else f"{coverage:.2%}",
                )
                lines.append("<tr>" + "".join(f"<td>{_html(c)}</td>" for c in cells))
                lines.append("</tr>")
    return "\n".join(lines) + "</tbody></table></div>"


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def render_html(report: dict[str, Any]) -> str:
    """Render an offline view. Full command/reason content is not anonymized."""
    status = _status(report)
    rows = report["results"]
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        f"script-src {_csp_hash(_SCRIPT)}; style-src {_csp_hash(_STYLE)}"
    )
    lines = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f'<meta http-equiv="Content-Security-Policy" content="{_html(csp)}">',
        "<title>charter-replay | Decision review</title>",
        f"<style>{_STYLE}</style></head><body><main>",
        '<header><span class="eyebrow">charter-replay / offline evidence</span>',
        "<h1>What changed in the guardrail?</h1>",
        '<p class="muted">Replay measures these inputs, not every reachable action. '
        "No corpus command was executed.</p></header>",
        '<section class="cards" aria-label="Comparison totals">',
        f'<div class="card gate-{status}">Gate<strong>{status.upper()}</strong></div>',
    ]
    for name, count in report["counts"].items():
        lines.append(f'<div class="card">{_html(name)}<strong>{count}</strong></div>')
    lines += [
        '</section><section class="panel"><h2>Evidence identity</h2>',
        f"<p>Corpus: <code>{_html(report['corpus']['id'])}</code><br>",
        f"Run: <code>{_html(report['run_id'])}</code></p>",
        "<p>Fail on: " + _html(", ".join(report["gate"]["fail_on"])) + "</p>",
    ]
    for side in ("baseline", "candidate"):
        failures = report["source_failures"][side]
        lines.append(
            f"<p><strong>{side.title()} source failures: {len(failures)}</strong></p>"
        )
        for failure in failures:
            lines.append(
                f"<p><code>{_html(failure['code'])}</code>: "
                f"{_html(failure['message'])} "
                f"<code>{_html(failure.get('event_id') or '')}</code></p>"
            )
    lines += [
        "</section><h2>Supplied-label agreement</h2>",
        "<p>These labels are not independent safety evidence. Dangerous/allow and "
        "benign/deny are disagreements with supplied labels, not certified errors. "
        "Rates include all cases in the class; indeterminate results remain visible. "
        "Opaque and unlabelled cases are excluded. Seed means non-generated origin, "
        "not independent adjudication. Declared origins do not verify lineage.</p>",
        _score_table(report),
        "<h2>Case-by-case review</h2>",
        '<p class="muted">Newly allowed dangerous cases appear first. This full report '
        "contains command text and hook reasons. Review it before sharing.</p>",
        '<section id="filters" class="panel" hidden aria-label="Case filters">',
        '<div class="filters">',
    ]
    attributes = [_attributes(row) for row in rows]
    for key, label in (
        ("class", "Case class"),
        ("family", "Family"),
        ("baseline", "Baseline effect"),
        ("candidate", "Candidate effect"),
        ("diff", "Diff class"),
        ("origin", "Declared origin"),
    ):
        lines.append(f'<div><label for="filter-{key}">{label}</label>')
        lines.append(f'<select id="filter-{key}"><option value="">All</option>')
        for value in sorted({attrs[key] for attrs in attributes}):
            lines.append(f'<option value="{_html(value)}">{_html(value)}</option>')
        lines.append("</select></div>")
    lines += [
        '<div><label for="search">Search visible text</label><input id="search" '
        'type="search" autocomplete="off"></div></div>',
        '<p><button id="reset" type="button">Reset filters</button></p></section>',
        "<noscript><p>JavaScript is disabled. "
        "All cases remain visible below.</p></noscript>",
        f'<p id="visible-count" aria-live="polite">{len(rows)} of {len(rows)} '
        "cases shown</p>",
        '<div class="table-wrap"><table class="case-table"><thead><tr>',
        "<th>Case / label</th><th>Command</th><th>Baseline</th><th>Candidate</th>",
        "<th>Change / origin</th></tr></thead><tbody>",
    ]
    for index, row in sorted(enumerate(rows), key=lambda item: _priority(item[1])):
        attrs = attributes[index]
        data = " ".join(f'data-{key}="{_html(value)}"' for key, value in attrs.items())
        lines.append(f'<tr id="case-{index}" data-case="{index}" {data}>')
        lines.append(
            f"<td><code>{_html(row['event']['event_id'])}</code>"
            f"<small>{_html(attrs['class'])} / {_html(attrs['family'])}</small></td>"
        )
        lines.append(f"<td><code>{_html(row['event']['command'])}</code></td>")
        for side in ("baseline", "candidate"):
            lines.append(
                f'<td><span class="badge">{_html(row[side]["effect"])}</span>'
                "<details><summary>Reason</summary>"
                f"<pre>{_html(row[side].get('reason') or '')}</pre></details></td>"
            )
        lines.append(
            f"<td>{_html(attrs['diff'])}"
            f"<small>{_html(attrs['origin'])}</small></td></tr>"
        )
    lines += [
        "</tbody></table></div><footer>",
        "Timing is observational and is not part of this view or run identity. "
        "Use measurements.json for latency and summary.json "
        "for qualified label metrics. "
        "A green replay is not a proof of safety.</footer></main>",
        f"<script>{_SCRIPT}</script></body></html>",
        "",
    ]
    return "\n".join(lines)


def _report_link(value: str | None) -> str:
    if value is None:
        return ""
    if len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("report link must be a bounded plain HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "\\" in value
    ):
        raise ValueError("report link must use HTTPS without credentials")
    return f'<a href="{_html(value)}" rel="noopener noreferrer">Full HTML report</a>\n'


def render_pr_comment(
    report: dict[str, Any],
    *,
    limit: int = 20,
    aggregate_only: bool = False,
    report_url: str | None = None,
) -> str:
    """Render bounded review text; aggregate mode includes no corpus identifiers."""
    if type(limit) is not int or not 0 <= limit <= 100:
        raise ValueError("comment limit must be an integer from 0 to 100")
    status = _status(report).upper()
    link = _report_link(report_url)
    lines = [
        "<!-- charter-replay:review.v1 -->",
        "## Guardrail replay",
        "",
        f"Gate: **{status}**",
        "",
        "| Diff class | Events |",
        "|---|---:|",
    ]
    for name in DIFF_CLASSES:
        count = report["counts"][name]
        lines.append(f"| {name} | {count} |")
    for side in ("baseline", "candidate"):
        count = len(report["source_failures"][side])
        lines.append(f"\n{side.title()} source failures: {count}.")
    footer = (
        "\n\nSupplied labels are not independent safety evidence. "
        "No corpus command was executed. A green replay is not a proof of safety.\n"
        + link
    )
    if aggregate_only:
        lines.append("\nCase and policy identifiers are omitted.")
        return "\n".join(lines) + footer
    changed = sorted(
        (row for row in report["results"] if row["classification"] != "unchanged"),
        key=_priority,
    )
    lines += ["", "### Changed cases (dangerous relaxations first)", ""]
    shown = 0
    for row in changed[:limit]:
        event_id = row["event"]["event_id"]
        preview = event_id[:160]
        if len(event_id) > 160:
            preview += " [identifier truncated]"
        label = (row.get("case") or {}).get("case_class", "unlabelled")
        line = (
            f"- {markdown_literal(preview)}: {markdown_literal(row['classification'])} "
            f"({markdown_literal(label)})."
        )
        size = len(("\n".join(lines) + line + footer).encode("utf-8"))
        if size > COMMENT_LIMIT_BYTES - 200:
            break
        lines.append(line)
        shown += 1
    lines.append(f"\n{shown} changed cases shown; {len(changed) - shown} omitted.")
    return "\n".join(lines) + footer
