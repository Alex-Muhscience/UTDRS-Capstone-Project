"""
The monthly report as a PDF, for printing, filing and sending to people without a UTDRS account.

Every piece of text from the data (titles, names) is escaped before it goes into a
paragraph: ReportLab paragraphs read markup, and an alert's title must stay text.
"""
from io import BytesIO
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ACCENT = colors.HexColor("#2563eb")
MUTED = colors.HexColor("#6b7280")
RULE = colors.HexColor("#e5e7eb")

FIGURES = [
    ("alerts", "Alerts raised", "{:.0f}"),
    ("cases_opened", "Cases opened", "{:.0f}"),
    ("critical_cases", "Critical cases", "{:.0f}"),
    ("cases_closed", "Cases dealt with", "{:.0f}"),
    ("actions_taken", "Response actions taken", "{:.0f}"),
    ("median_hours_to_resolve", "Typical time to deal with a case (hours)", "{:.1f}"),
    ("within_deadline_percent", "Dealt with within deadline", "{:.0f}%"),
]


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], alignment=0, fontSize=20, spaceAfter=2),
        "subtitle": ParagraphStyle("subtitle", parent=base["Normal"], textColor=MUTED, spaceAfter=10),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13, textColor=ACCENT, spaceBefore=12, spaceAfter=6, keepWithNext=1),
        "body": ParagraphStyle("body", parent=base["Normal"], fontSize=10, leading=14),
        "small": ParagraphStyle("small", parent=base["Normal"], fontSize=8, textColor=MUTED),
    }


def _text(value: Any) -> str:
    return escape(str(value))


def _format(value: Optional[float], pattern: str) -> str:
    return "—" if value is None else pattern.format(value)


def _change(value: Optional[float], previous: Optional[float]) -> str:
    if value is None or previous is None:
        return ""
    if previous == 0:
        return "new" if value else "no change"
    percent = round(100 * (value - previous) / previous)
    return "no change" if percent == 0 else f"{'+' if percent > 0 else ''}{percent}%"


def _table(rows: List[List[Any]], widths: List[float], header: bool = True) -> Table:
    table = Table(rows, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("TEXTCOLOR", (0, 0), (-1, 0), MUTED), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    table.setStyle(TableStyle(style))
    return table


def _weekly_chart(weeks: List[Dict[str, Any]]) -> Drawing:
    drawing = Drawing(170 * mm, 45 * mm)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 10 * mm, 8 * mm, 155 * mm, 33 * mm
    chart.data = [[week["count"] for week in weeks] or [0]]
    chart.categoryAxis.categoryNames = [f"{week['start']:%d %b}" for week in weeks] or [""]
    chart.categoryAxis.labels.fontName = chart.valueAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max([week["count"] for week in weeks] + [1])
    chart.valueAxis.labels.fontSize = 7
    chart.bars[0].fillColor = ACCENT
    chart.bars[0].strokeColor = None
    drawing.add(chart)
    return drawing


def render(report: Dict[str, Any]) -> bytes:
    data = report["data"]
    s = _styles()
    p = lambda text, style="body": Paragraph(text, s[style])  # noqa: E731 - text is already escaped
    story: List[Any] = [
        p(f"Security report: {_text(data['title'])}", "title"),
        p(f"{_text(data['organisation'])} · made {report['generated_at']:%d %B %Y}", "subtitle"),
    ]
    for line in data["headline"]:
        story.append(p(_text(line)))
    story += [Spacer(1, 4), p("What to do next", "h2")]
    story += [p(f"• {_text(line)}") for line in data["recommendations"]]

    story.append(p("The month in figures", "h2"))
    rows = [["", data["title"], "Month before", "Change"]]
    for key, label, pattern in FIGURES:
        figure = data["figures"][key]
        rows.append([label, _format(figure["value"], pattern), _format(figure["previous"], pattern), _change(figure["value"], figure["previous"])])
    story.append(_table(rows, [75 * mm, 30 * mm, 30 * mm, 25 * mm]))

    story += [p("Alerts each week", "h2"), _weekly_chart(data["weekly_alerts"])]
    severities = data["alerts_by_severity"]
    if severities:
        order = ["critical", "high", "medium", "low", "info"]
        story.append(p(_text(", ".join(f"{severities[k]} {k}" for k in order if severities.get(k))), "small"))

    if data["top_threats"]:
        story.append(p("What the threats were", "h2"))
        story.append(_table([["Threat", "Alerts"]] + [[p(_text(t["name"])), t["count"]] for t in data["top_threats"]], [140 * mm, 20 * mm]))
    if data["most_targeted"]:
        story.append(p("Most often involved", "h2"))
        story.append(_table([["Who or what", "", "Cases"]] + [[p(_text(t["name"])), t["type"].capitalize(), t["cases"]] for t in data["most_targeted"]],
                            [110 * mm, 30 * mm, 20 * mm]))

    actions = data["actions"]
    story.append(p("What UTDRS did", "h2"))
    if actions["taken"]:
        story.append(p(_text(
            f"{actions['taken']} response action{'s' if actions['taken'] != 1 else ''} taken: {actions['automatic']} on its own, "
            f"{actions['approved']} approved by your people. {actions['undone']} undone, {actions['rejected']} turned down, {actions['failed']} failed."
        )))
        story.append(_table([["Action", "Times"]] + [[p(_text(a["label"])), a["count"]] for a in actions["by_action"]], [140 * mm, 20 * mm]))
    else:
        story.append(p("No response actions were taken this month."))

    outstanding = data["outstanding"]
    story.append(p("Still open", "h2"))
    if outstanding["open_cases"]:
        story.append(p(_text(
            f"{outstanding['open_cases']} open case{'s' if outstanding['open_cases'] != 1 else ''}, {outstanding['overdue']} overdue; "
            f"{outstanding['awaiting_approval']} action{'s' if outstanding['awaiting_approval'] != 1 else ''} waiting for approval."
        )))
        story.append(_table(
            [["Case", "Priority", "Due"]]
            + [[p(_text(c["title"])), c["priority"].capitalize(), f"{c['due_at']:%d %b %H:%M}{' (overdue)' if c['overdue'] else ''}"] for c in outstanding["top"]],
            [105 * mm, 25 * mm, 35 * mm],
        ))
    else:
        story.append(p("No cases are open."))

    story += [Spacer(1, 10), p("Times are UTC. Made by UTDRS from your organisation's alerts, cases and response actions.", "small")]

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Security report: {data['title']}", author="UTDRS",
    )
    document.build(story)
    return buffer.getvalue()
