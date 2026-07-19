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

from ovs_logs.core.timeline import TimelineRow, build_timeline
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
                marker=dict(color=color_hex, size=9, opacity=0.85),
                name=_LEGEND_LABELS[color_label],
                customdata=[(event_types[i], statuses[i], messages[i]) for i in indices],
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "Time: %{x}<br>"
                    "Type: %{customdata[0]}<br>"
                    "Status: %{customdata[1]}<br>"
                    "%{customdata[2]}"
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
        margin=dict(l=0, r=0, t=30, b=0),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
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
    full_rows: list[TimelineRow],
) -> tuple[list[str], int | None, list[str]]:
    """Render filter widgets and return selected values."""
    all_ips = sorted(
        {r.source_ip for r in full_rows if r.source_ip},
        key=lambda ip: -sum(1 for r in full_rows if r.source_ip == ip),
    )
    all_event_types = sorted({r.event_type for r in full_rows if r.event_type})

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
            options=all_event_types,
            default=[],
            key="tl_filter_event_type",
        )

    return selected_ips, min_status, selected_event_types


def _apply_client_side_filters(
    rows: list[TimelineRow],
    selected_ips: list[str],
    selected_event_types: list[str],
) -> list[TimelineRow]:
    """Apply multi-select filters that cannot be pushed to SQL."""
    result = rows
    if len(selected_ips) > 1:
        ip_set = set(selected_ips)
        result = [r for r in result if r.source_ip in ip_set]
    if len(selected_event_types) > 1:
        et_set = set(selected_event_types)
        result = [r for r in result if r.event_type in et_set]
    return result


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
        selected_indices = [p.get("point_index", -1) for p in point_data if "point_index" in p]

    if selected_indices:
        selected_rows = [rows[i] for i in selected_indices if 0 <= i < len(rows)]
        st.subheader(f"Selected events ({len(selected_rows)})")
        _render_detail_cards(selected_rows)
    else:
        show_rows = rows[:10]
        if show_rows:
            st.subheader("Recent events")
            _render_detail_cards(show_rows)

    if metrics_total > len(rows):
        st.caption(f"Showing {len(rows)} of {metrics_total} events. Use filters to narrow results.")


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
        _full_metrics, full_rows = build_timeline(connection, table_name)
    except duckdb.Error:
        logger.exception("Failed to build timeline for table %s", table_name)
        st.error("Timeline failed while querying this table.")
        return

    if _full_metrics.total_events == 0:
        st.info("No events found in this table.")
        return

    selected_ips, min_status, selected_event_types = _render_filters(full_rows)

    # Server-side filter for single-value selections
    filter_ip = selected_ips[0] if len(selected_ips) == 1 else None
    filter_event_type = selected_event_types[0] if len(selected_event_types) == 1 else None

    try:
        metrics, rows = build_timeline(
            connection,
            table_name,
            source_ip=filter_ip,
            min_status=min_status,
            event_type=filter_event_type,
        )
    except duckdb.Error:
        logger.exception("Failed to build timeline for table %s", table_name)
        st.error("Timeline failed while querying this table.")
        return

    rows = _apply_client_side_filters(rows, selected_ips, selected_event_types)

    cols = st.columns(4)
    cols[0].metric("Total events", metrics.total_events)
    cols[1].metric("Time span", metrics.duration or "n/a")
    cols[2].metric("Unique source IPs", metrics.unique_source_ips)
    cols[3].metric("Error rate", f"{metrics.error_rate_pct}%")

    _render_chart_and_cards(rows, metrics.total_events)
