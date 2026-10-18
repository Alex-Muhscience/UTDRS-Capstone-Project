"""Monthly reports: a month of security in plain words, on the web and as a PDF."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status

from api.routes.response import actor_of
from core.models.report import Report, ReportRequest, ReportSummary
from core.models.user import User
from core.services import audit, report_pdf, reports
from utils.security import get_current_active_user
from utils.time import utcnow

router = APIRouter()


def _found(report):
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("/", response_model=List[ReportSummary])
async def list_reports(current_user: User = Depends(get_current_active_user)):
    """Your organisation's reports, newest month first."""
    return [{**r, "title": r["data"]["title"], "headline": r["data"]["headline"]} for r in await reports.list_reports()]


@router.post("/", response_model=Report, status_code=status.HTTP_201_CREATED)
async def make_report(request: Request, body: ReportRequest = ReportRequest(), current_user: User = Depends(get_current_active_user)):
    """
    Make the report for a month (by default the last full month), or make it again with
    today's figures for what is still open. The month must have started.
    """
    period = body.period or reports.last_full_month()
    if period > f"{utcnow():%Y-%m}":
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="That month has not started yet")
    report = await reports.generate(period, actor_of(request))
    audit.created(request, "report", str(report["_id"]), period)
    return report


@router.get("/{report_id}", response_model=Report)
async def get_report(report_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    return _found(await reports.get(report_id))


@router.get("/{report_id}/pdf", response_class=Response, responses={200: {"content": {"application/pdf": {}}}})
async def report_as_pdf(report_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """The report as a PDF."""
    report = _found(await reports.get(report_id))
    return Response(
        report_pdf.render(report), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="utdrs-report-{report["period"]}.pdf"'},
    )
