"""Core-layer formatter for rendering analysis results as Markdown and structured context.

This module provides presentation-layer formatting utilities that operate on
core-layer data structures. It is independent of the CLI and UI layers and
can be used by any presentation consumer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FormatterConfig:
    """Configuration for context formatting."""

    title: str = "Analysis Results"
    max_cell_width: int = 50
    max_rows: int = 100
    max_bullets: int = 100


@dataclass(frozen=True)
class FormattedContext:
    """Rendered and structured representations of analysis results.

    Attributes:
        markdown: Human-readable Markdown representation.
        structured: Structured dictionary with title, summary, tables,
            and LLM-ready bullet points.
    """

    markdown: str
    structured: dict[str, Any]


def _escape_cell(value: str, max_width: int) -> str:
    """Escape Markdown-sensitive characters and truncate to max_width."""
    escaped = value.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    if len(escaped) > max_width:
        return escaped[:max_width] + "..."
    return escaped


def _first_readable_value(row: dict[str, Any]) -> str:
    """Render all relevant non-null field values from a row."""
    parts: list[str] = []
    for key, value in row.items():
        if value is None:
            continue
        if isinstance(value, str | int | float):
            parts.append(f"{key}={value}")
    if parts:
        return ", ".join(parts)
    return str(row)


def format_context(
    results: dict[str, list[dict[str, Any]]],
    config: FormatterConfig,
) -> FormattedContext:
    """Convert analysis results into structured Markdown and structured dict.

    Args:
        results: Dict mapping template name to list of result row dicts.
        config: FormatterConfig with title, max_cell_width, max_rows, max_bullets.

    Returns:
        FormattedContext with markdown and structured fields.
    """
    total_findings = sum(len(rows) for rows in results.values())

    structured: dict[str, Any] = {
        "title": config.title,
        "summary": {"templates_executed": len(results), "total_findings": total_findings},
        "tables": dict(results),
    }

    llm_bullets: list[str] = []
    for name, rows in results.items():
        for row in rows:
            bullet_text = _first_readable_value(row)
            escaped_text = _escape_cell(bullet_text, config.max_cell_width)
            llm_bullets.append(f"[{name}] {escaped_text}")

    structured["llm_bullets"] = llm_bullets[: config.max_bullets]

    if not results or total_findings == 0:
        markdown = f"# {config.title}\n\nNo findings."
    else:
        parts: list[str] = []
        parts.append(f"# {config.title}")
        parts.append("")
        parts.append("## Summary")
        parts.append(f"Templates executed: {len(results)}")
        parts.append(f"Total findings: {total_findings}")
        parts.append("")

        for name, rows in results.items():
            if not rows:
                continue
            parts.append(f"## {name}")
            columns = list(rows[0].keys())
            parts.append("| " + " | ".join(columns) + " |")
            parts.append("|" + "|".join("---" for _ in columns) + "|")

            displayed_rows = rows[: config.max_rows]
            for row in displayed_rows:
                cells: list[str] = []
                for col in columns:
                    val = row.get(col)
                    if val is None:
                        cells.append("\u2014")
                    else:
                        s = str(val)
                        cells.append(_escape_cell(s, config.max_cell_width))
                parts.append("| " + " | ".join(cells) + " |")
            parts.append("")

        parts.append("## Context for LLM")
        parts.extend(f"- {bullet}" for bullet in llm_bullets[: config.max_bullets])

        markdown = "\n".join(parts)

    return FormattedContext(markdown=markdown, structured=structured)
