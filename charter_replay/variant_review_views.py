"""Internal review renderers; evidence admission lives in variant_review."""

from __future__ import annotations

from typing import Any

from charter_replay.compare import DIFF_CLASSES
from charter_replay.corpus import DECISION_EFFECTS
from charter_replay.review_reports import COMMENT_LIMIT_BYTES, _html
from charter_replay.review_reports import render_html, render_pr_comment

NOTICE = (
    "Source, pack, report rows and run-manifest consistency are checked. "
    "Decisions and source-failure claims are not authenticated execution evidence. "
    "Inherited labels and correlated shapes are not independent safety votes. "
    "Even identifier-free small counts can disclose private corpus information."
)


def _table(caption, headings, rows) -> str:
    parts = ['<div class="table-wrap"><table>', f"<caption>{_html(caption)}</caption>",
             "<thead><tr>" + "".join(f'<th scope="col">{_html(value)}</th>' for value in headings),
             "</tr></thead><tbody>"]
    for row in rows:
        parts.append("<tr>" + "".join(f"<td>{_html(value)}</td>" for value in row) + "</tr>")
    parts.append("</tbody></table></div>")
    return "\n".join(parts)


def _coverage_section(coverage: dict[str, Any], details: dict[str, Any]) -> str:
    counts = coverage["counts"]
    clusters = coverage["clusters"]
    shapes = details["shape_disagreements"]
    parts = [
        '<section id="variant-review" aria-labelledby="variant-review-title">',
        '<h2 id="variant-review-title">Verified seed and shape coverage</h2>',
        f"<p>{_html(NOTICE)}</p>",
        '<div class="cards">',
        f'<div class="card">Seed cases<strong>{counts["seeds"]}</strong></div>',
        f'<div class="card">Derived cases<strong>{counts["derived"]}</strong></div>',
        f'<div class="card">Skipped transform attempts<strong>{counts["skipped"]}</strong></div>',
        '<div class="card">Unchanged seeds with changed variants<strong>'
        f'{clusters["unchanged_seeds_with_changed_variants"]}</strong></div>',
        '<div class="card">Shared shape disagreements<strong>'
        f'{shapes["shared"]["variants"]}</strong>'
        f'<small>{shapes["shared"]["seeds"]} distinct seeds</small></div></div>',
        "<p>Changed variants under unchanged seeds are cross-version changes. "
        "Shared shape disagreements are identical, nontrivial seed-to-shape "
        "transitions in both versions, even though their cross-version diff is "
        "unchanged. These observations do not add a safety gate.</p>",
        _table("Cross-version changes by verified origin", ("Diff class", "Seed", "Derived"), [
            (name, coverage["by_origin"]["seed"][name], coverage["by_origin"]["derived"][name])
            for name in DIFF_CLASSES
        ]),
        _table("Transform coverage", ("Transform", "Generated", "Skipped", "Changed"), [
            (name, row["generated"], row["skipped"], row["generated"] - row["changes"]["unchanged"])
            for name, row in coverage["by_transform"].items()
        ]),
        '<details class="panel"><summary>Seed to shape effects</summary>',
        "<p>Each cell counts a seed-effect to variant-effect transition within "
        "one policy, not a baseline-to-candidate transition. Indeterminate is "
        "separate from allow and deny. Multiple shapes can share a seed.</p>",
    ]
    for name, row in coverage["by_transform"].items():
        parts.append(_table(name, ("Seed effect", "Shape effect", "Baseline", "Candidate"), [
            (before, after, row["shape_effects"]["baseline"][f"{before}->{after}"],
             row["shape_effects"]["candidate"][f"{before}->{after}"])
            for before in sorted(DECISION_EFFECTS) for after in sorted(DECISION_EFFECTS)
        ]))
    parts.append("</details></section>")
    return "\n".join(parts)


def _coverage_text(coverage: dict[str, Any], details: dict[str, Any]) -> str:
    counts = coverage["counts"]
    clusters = coverage["clusters"]
    shapes = details["shape_disagreements"]
    lines = [
        "\n### Verified seed and shape coverage\n",
        f'Seeds: {counts["seeds"]}; derived: {counts["derived"]}; '
        f'skipped transform attempts: {counts["skipped"]}.',
        "Unchanged seeds with changed variants: "
        f'{clusters["unchanged_seeds_with_changed_variants"]}.',
        "Shared shape disagreements: "
        f'{shapes["shared"]["variants"]} variants across {shapes["shared"]["seeds"]} seeds.',
        "Shared means the same nontrivial seed-to-shape transition in both versions, "
        "not a new cross-version regression.",
        "\n| Origin | Newly allowed | Newly denied | Newly indeterminate | Resolved indeterminate | Unchanged |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for origin, row in coverage["by_origin"].items():
        lines.append(f'| {origin} | {row["newly-allowed"]} | {row["newly-denied"]} | '
                     f'{row["newly-indeterminate"]} | {row["resolved-indeterminate"]} | {row["unchanged"]} |')
    lines += ["\n| Transform | Generated | Skipped | Changed |", "|---|---:|---:|---:|"]
    for name, row in coverage["by_transform"].items():
        changed = row["generated"] - row["changes"]["unchanged"]
        lines.append(f'| {name} | {row["generated"]} | {row["skipped"]} | {changed} |')
    lines.extend(["", "Full effect matrices are in report.html from this review bundle.", NOTICE, ""])
    return "\n".join(lines)


def render_review_views(
    report: dict[str, Any], coverage: dict[str, Any], details: dict[str, Any]
) -> dict[str, bytes]:
    """Internal renderer: callers must admit all three values from one capture."""
    marker = "<h2>Supplied-label agreement</h2>"
    markup = render_html(report)
    if markup.count(marker) != 1:
        raise ValueError("review template does not have its unique coverage insertion point")
    markup = markup.replace(marker, _coverage_section(coverage, details) + marker, 1)
    section = _coverage_text(coverage, details)
    result = {"report.html": markup.encode("utf-8")}
    for aggregate, name in ((False, "pr-comment.md"), (True, "pr-comment-aggregate.md")):
        # Reserve space for coverage rather than truncating a UTF-8/Markdown row.
        for limit in range(20, -1, -1):
            text = render_pr_comment(report, aggregate_only=aggregate, limit=limit) + section
            data = text.encode("utf-8")
            if len(data) <= COMMENT_LIMIT_BYTES:
                result[name] = data
                break
        else:
            raise ValueError("review comment exceeds its byte budget")
    return result
