"""Attack-timeline rendering for the OVS-Log Streamlit dashboard.

Renders an interactive Plotly scatter chart on a time axis, with filter widgets
for source IP, minimum status code, and event type. Clicking a dot shows
event detail cards below the chart. Degrades gracefully for non-analyzable or
empty tables and query errors.
"""

from __future__ import annotations

import logging

import duckdb
import plotly.graph_objects as go
import streamlit as st

from ovs_logs.core.timeline import TimelineMetrics, TimelineRow, build_timeline, list_timeline_filter_options
from ovs_logs.ui.analysis_view import has_analyzable_columns

logger = logging.getLogger(__name__)

_STATUS_COLORS: dict[str, str] = {
    "success": "#4CAF50",
    "redirect": "#FFC107",
    "client_error": "#FF9800",
    "server_error": "#f44336",
    "unknown": "#888888",
}

_LEGEND_LABELS: dict[str, str] = {
    "success": "2xx Success",
    "redirect": "3xx Redirect",
    "client_error": "4xx Client Error",
    "server_error": "5xx Server Error",
    "unknown": "Unknown",
}

_STATUS_THRESHOLDS = (300, 400, 500)
_MSG_TRUNCATE_LEN = 80
_MAX_DETAIL_CARDS = 20


def _status_color(status_code: int | None) -> str:
    """Map an HTTP status code to a color string."""
    if status_code is None:
        return _STATUS_COLORS["unknown"]
    if status_code < _STATUS_THRESHOLDS[0]:
        return _STATUS_COLORS["success"]
    if status_code < _STATUS_THRESHOLDS[1]:
        return _STATUS_COLORS["redirect"]
    if status_code < _STATUS_THRESHOLDS[2]:
        return _STATUS_COLORS["client_error"]
    return _STATUS_COLORS["server_error"]


def _truncate(msg: str) -> str:
    """Truncate a message to ``_MSG_TRUNCATE_LEN`` characters."""
    if len(msg) > _MSG_TRUNCATE_LEN:
        return msg[:_MSG_TRUNCATE_LEN] + "..."
    return msg


def _build_scatter_chart(rows: list[TimelineRow]) -> go.Figure:
    """Create a Plotly scatter chart from timeline rows."""
    if not rows:
        return go.Figure()

    timestamps = [r.timestamp for r in rows]
    ips = [r.source_ip or "unknown" for r in rows]
    statuses = [r.status_code for r in rows]
    event_types = [r.event_type or "N/A" for r in rows]
    messages = [_truncate(r.raw_message or "") for r in rows]
    colors = [_status_color(s) for s in statuses]

    fig = go.Figure()

    for color_label, color_hex in _STATUS_COLORS.items():
        indices = [i for i, c in enumerate(colors) if c == color_hex]
        if not indices:
            continue
        fig.add_trace(
            go.Scatter(
                x=[timestamps[i] for i in indices],
                y=[ips[i] for i in indices],
                mode="markers",
                marker={"color": color_hex, "size": 9, "opacity": 0.85},
                name=_LEGEND_LABELS[color_label],
                customdata=[(i, event_types[i], statuses[i], messages[i]) for i in indices],
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "Time: %{x}<br>"
                    "Type: %{customdata[1]}<br>"
                    "Status: %{customdata[2]}<br>"
                    "%{customdata[3]}"
                    "<extra></extra>"
                ),
                legendgroup=color_label,
                showlegend=True,
            )
        )

    unique_ip_count = len(set(ips))
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Source IP",
        height=max(300, min(600, unique_ip_count * 30 + 100)),
        margin={"l": 0, "r": 0, "t": 30, "b": 0},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1},
        hovermode="closest",
        template="plotly_dark",
    )
    fig.update_xaxes(rangeslider_visible=False)

    return fig


def _render_detail_cards(selected_rows: list[TimelineRow]) -> None:
    """Show selected events as expandable detail cards."""
    if not selected_rows:
        return

    for i, row in enumerate(selected_rows[:_MAX_DETAIL_CARDS]):
        ts_str = row.timestamp.strftime("%Y-%m-%d %H:%M:%S") if row.timestamp else "N/A"
        status_str = str(row.status_code) if row.status_code is not None else "N/A"
        ip_str = row.source_ip or "N/A"
        et_str = row.event_type or "N/A"
        title = f"Event {i + 1}: {ts_str} | {ip_str} | {et_str} | {status_str}"
        with st.expander(title):
            c1, c2, c3 = st.columns(3)
            c1.metric("Source IP", ip_str)
            c2.metric("Event Type", et_str)
            c3.metric("Status", status_str)
            if row.raw_message:
                st.code(row.raw_message, language="text")

    if len(selected_rows) > _MAX_DETAIL_CARDS:
        st.caption(f"Showing {_MAX_DETAIL_CARDS} of {len(selected_rows)} selected events.")


def _render_filters(
    ip_counts: list[tuple[str, int]],
    event_types: list[str],
) -> tuple[list[str], int | None, list[str]]:
    """Render filter widgets and return selected values.

    Args:
        ip_counts: ``[(source_ip, frequency)]`` ordered by frequency descending.
        event_types: Sorted list of distinct event types.

    Returns:
        ``(selected_ips, min_status, selected_event_types)``.
    """
    all_ips = [ip for ip, _ in ip_counts]
    col1, col2, col3 = st.columns(3)
    with col1:
        selected_ips: list[str] = st.multiselect(
            "Source IP",
            options=all_ips,
            default=[],
            key="tl_filter_ip",
        )
    with col2:
        min_status_options = {"All": None, ">= 3xx": 300, ">= 4xx": 400, ">= 5xx": 500}
        min_status_label = st.selectbox(
            "Status code",
            options=list(min_status_options.keys()),
            index=0,
            key="tl_filter_status",
        )
        min_status = min_status_options[min_status_label]
    with col3:
        selected_event_types: list[str] = st.multiselect(
            "Event type",
            options=event_types,
            default=[],
            key="tl_filter_event_type",
        )

    return selected_ips, min_status, selected_event_types


def _render_chart_and_cards(
    rows: list[TimelineRow],
    metrics_total: int,
) -> None:
    """Render the Plotly scatter chart and event detail cards."""
    fig = _build_scatter_chart(rows)
    selection = st.plotly_chart(
        fig,
        width="stretch",
        on_select="rerun",
        key="tl_scatter",
    )

    selected_indices: list[int] = []
    if selection and isinstance(selection, dict):
        point_data = selection.get("selection", {}).get("points", [])
        for p in point_data:
            customdata = p.get("customdata")
            if customdata and len(customdata) > 0:
                idx = customdata[0]
                if isinstance(idx, int) and 0 <= idx < len(rows):
                    selected_indices.append(idx)

    if selected_indices:
        # Deduplicate and preserve selection order
        seen: set[int] = set()
        unique_indices: list[int] = []
        for idx in selected_indices:
            if idx not in seen:
                seen.add(idx)
                unique_indices.append(idx)
        selected_rows = [rows[i] for i in unique_indices]
        st.subheader(f"Selected events ({len(selected_rows)})")
        _render_detail_cards(selected_rows)
    else:
        show_rows = rows[-10:][::-1]
        if show_rows:
            st.subheader("Recent events")
            _render_detail_cards(show_rows)

    if metrics_total > len(rows):
        st.caption(f"Showing {len(rows)} of {metrics_total} events. Use filters to narrow results.")


def _get_timeline_data(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    source_ip: list[str] | str | None = None,
    min_status: int | None = None,
    event_type: list[str] | str | None = None,
) -> tuple[TimelineMetrics, list[TimelineRow]] | None:
    """Call :func:`build_timeline` with error handling.

    Returns ``None`` (and renders ``st.error``) on failure so the caller can
    short-circuit gracefully.
    """
    try:
        return build_timeline(
            connection,
            table_name,
            source_ip=source_ip,
            min_status=min_status,
            event_type=event_type,
        )
    except duckdb.Error:
        logger.exception("Failed to build timeline for table %s", table_name)
        st.error("Timeline failed while querying this table.")
        return None


def render_timeline_card(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
) -> None:
    """Render the Attack Timeline: metric tiles, scatter chart, filters, detail cards.

    Degrades gracefully for non-analyzable / empty tables and query errors.
    """
    if not has_analyzable_columns(connection, table_name):
        st.info("No analyzable fields in this table")
        return

    try:
        ip_counts, event_types = list_timeline_filter_options(connection, table_name)
    except duckdb.Error:
        logger.exception("Failed to load filter options for table %s", table_name)
        st.error("Timeline failed while querying this table.")
        return

    if not ip_counts and not event_types:
        st.info("No events found in this table.")
        return

    selected_ips, min_status, selected_event_types = _render_filters(ip_counts, event_types)

    result = _get_timeline_data(
        connection,
        table_name,
        source_ip=selected_ips or None,
        min_status=min_status,
        event_type=selected_event_types or None,
    )
    if result is None:
        return
    metrics, rows = result

    cols = st.columns(4)
    cols[0].metric("Total events", metrics.total_events)
    cols[1].metric("Time span", metrics.duration or "n/a")
    cols[2].metric("Unique source IPs", metrics.unique_source_ips)
    cols[3].metric("Error rate", f"{metrics.error_rate_pct}%")

    _render_chart_and_cards(rows, metrics.total_events)
