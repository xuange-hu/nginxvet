"""Generate docs/rules.md from the registry (single source of truth)."""

from __future__ import annotations

from .rules import REGISTRY, STAGES


def full_markdown() -> str:
    table = sorted(REGISTRY, key=lambda item: item.id)
    counts: dict[str, int] = {}
    for item in table:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    names = ("critical", "high", "medium", "low", "note")
    breakdown = ", ".join(f"{counts[name]} {name}" for name in names if name in counts)
    stage_names = ", ".join(f"`{stage}`" for stage in STAGES)

    out = [
        "# nginxvet rules",
        "",
        f"{len(table)} rules ({breakdown}), in three passes: {stage_names}.",
        "",
        "- `directive` (NGV1xx) — a single directive and the value it exposes.",
        "- `relation` (NGV2xx) — server/location relationships and inheritance.",
        "- `crossfile` (NGV3xx) — what include expansion does to the effective tree.",
        "",
        "Every finding carries path, line, byte offset and the raw snippet.",
        "",
    ]
    for item in table:
        out += [
            f"## {item.id}",
            "",
            f"**{item.title}**",
            "",
            f"- severity: {item.severity} (score {item.score}/10)",
            f"- pass: {item.stage}",
            "",
            item.why,
            "",
            f"**Fix:** {item.fix}",
            "",
        ]
    return "\n".join(out)
